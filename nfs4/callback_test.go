package nfs4

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

func TestParseUniversalAddr(t *testing.T) {
	tests := []struct {
		netid, uaddr string
		want         string // "" means an error
	}{
		{"tcp", "10.0.0.1.8.1", "10.0.0.1:2049"},
		{"tcp", "127.0.0.1.3.232", "127.0.0.1:1000"},
		{"tcp", "255.255.255.254.255.255", "255.255.255.254:65535"},
		{"tcp6", "::1.8.1", "[::1]:2049"},
		{"tcp6", "fe80::1.8.1", "[fe80::1]:2049"},
		{"tcp", "", ""},
		{"tcp", "10.0.0.1", ""},
		{"tcp", "10.0.0.1.8", ""},
		{"tcp", "10.0.0.1.8.1.2", ""},
		{"tcp", "10.0.0.256.8.1", ""},
		{"tcp", "10.0.0.1.256.1", ""},
		{"tcp", "10.0.0.1.8.256", ""},
		{"tcp", "10.0.0.1.+8.1", ""},
		{"tcp", "10.0.0.1.8.-1", ""},
		{"tcp", "10.0.0.1.a.b", ""},
		{"tcp", "banana.8.1", ""},
		{"tcp", "10.0.0.1.0.0", ""},  // port zero
		{"tcp", "0.0.0.0.8.1", ""},   // unspecified address
		{"tcp", "::1.8.1", ""},       // family does not match the netid
		{"tcp6", "10.0.0.1.8.1", ""}, // family does not match the netid
		{"tcp6", "::.8.1", ""},       // unspecified address
		{"udp", "10.0.0.1.8.1", ""},  // unsupported netid
		{"", "10.0.0.1.8.1", ""},
	}
	for _, tt := range tests {
		got, err := parseUniversalAddr(tt.netid, tt.uaddr)
		if tt.want == "" {
			if err == nil {
				t.Errorf("parseUniversalAddr(%q, %q) = %q, want error", tt.netid, tt.uaddr, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("parseUniversalAddr(%q, %q) = %q, %v, want %q", tt.netid, tt.uaddr, got, err, tt.want)
		}
	}
}

const testCBIdent = 7

// cbNullServer is the in-process callback service: a listener that can be
// told to answer CB_NULL, to stall, or to refuse. Received CB_RECALLs are
// reported on the recalls channel; recallMode "ignore" swallows them without
// answering, which is how a client that never returns behaves.
type cbNullServer struct {
	t          *testing.T
	l          net.Listener
	program    uint32
	mode       string // "answer", "stall", "refuse"
	recallMode string // "" or "answer", "ignore"
	recalls    chan wireStateid

	mu    sync.Mutex
	conns []net.Conn
}

func startCBNullServer(t *testing.T, program uint32, mode string) *cbNullServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cb := &cbNullServer{t: t, l: l, program: program, mode: mode,
		recalls: make(chan wireStateid, 8)}
	go cb.serve()
	t.Cleanup(cb.close)
	return cb
}

func (cb *cbNullServer) close() {
	cb.l.Close()
	cb.mu.Lock()
	defer cb.mu.Unlock()
	for _, c := range cb.conns {
		c.Close()
	}
}

func (cb *cbNullServer) serve() {
	for {
		c, err := cb.l.Accept()
		if err != nil {
			return
		}
		cb.mu.Lock()
		cb.conns = append(cb.conns, c)
		cb.mu.Unlock()
		go cb.handle(c)
	}
}

func (cb *cbNullServer) handle(c net.Conn) {
	if cb.mode == "stall" {
		return // hold the connection open and never answer
	}
	for {
		record, err := readRecord(c, 4096)
		if err != nil {
			return
		}
		d := xdr.NewDecoder(record)
		xid := d.Uint32()
		if mtype := d.Uint32(); mtype != msgCall {
			cb.t.Errorf("callback mtype = %d, want %d", mtype, msgCall)
		}
		if vers := d.Uint32(); vers != rpcVersion {
			cb.t.Errorf("callback rpcvers = %d, want %d", vers, rpcVersion)
		}
		if prog := d.Uint32(); prog != cb.program {
			cb.t.Errorf("callback program = %d, want %d", prog, cb.program)
		}
		if vers := d.Uint32(); vers != callbackVersion {
			cb.t.Errorf("callback version = %d, want %d", vers, callbackVersion)
		}
		proc := d.Uint32()
		d.Uint32()             // cred flavor
		d.Opaque(maxCredBytes) // cred body
		d.Uint32()             // verf flavor
		d.Opaque(maxCredBytes) // verf body

		e := xdr.NewEncoder(nil)
		e.Uint32(xid)
		e.Uint32(msgReply)
		if cb.mode == "refuse" {
			e.Uint32(replyDenied)
			e.Uint32(rejectAuthError)
			e.Uint32(authBadCred)
			writeRecord(c, e.Bytes())
			continue
		}
		e.Uint32(replyAccepted)
		e.Uint32(authNone)
		e.Uint32(0)
		e.Uint32(acceptSuccess)
		switch proc {
		case cbProcNull:
		case cbProcCompound:
			d.Opaque(maxTagBytes) // tag
			if minor := d.Uint32(); minor != 0 {
				cb.t.Errorf("CB_COMPOUND minorversion = %d", minor)
			}
			if ident := d.Uint32(); ident != testCBIdent {
				cb.t.Errorf("CB_COMPOUND callback_ident = %d, want %d", ident, testCBIdent)
			}
			if n := d.Uint32(); n != 1 {
				cb.t.Errorf("CB_COMPOUND carries %d ops, want 1", n)
			}
			if op := d.Uint32(); op != opCBRecall {
				cb.t.Errorf("CB_COMPOUND op = %d, want CB_RECALL", op)
			}
			state := getStateid(d)
			d.Bool() // truncate
			d.Opaque(maxFHBytes)
			if d.Err() != nil {
				cb.t.Errorf("CB_RECALL decode: %v", d.Err())
			}
			cb.recalls <- state
			if cb.recallMode == "ignore" {
				continue
			}
			e.Uint32(uint32(nfs4OK)) // CB_COMPOUND status
			e.Opaque(nil)            // tag
			e.Uint32(1)              // one result
			e.Uint32(opCBRecall)
			e.Uint32(uint32(nfs4OK))
		default:
			cb.t.Errorf("callback proc = %d", proc)
		}
		writeRecord(c, e.Bytes())
	}
}

// uaddr renders the listener's address in the universal form SETCLIENTID
// carries.
func (cb *cbNullServer) uaddr() string {
	host, portStr, err := net.SplitHostPort(cb.l.Addr().String())
	if err != nil {
		cb.t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		cb.t.Fatal(err)
	}
	return fmt.Sprintf("%s.%d.%d", host, port/256, port%256)
}

func TestPingCallback(t *testing.T) {
	answer := startCBNullServer(t, 0x40000000, "answer")
	if err := pingCallback(callbackPath{program: 0x40000000, addr: answer.l.Addr().String()}); err != nil {
		t.Errorf("ping of an answering path = %v, want nil", err)
	}

	refuse := startCBNullServer(t, 0x40000000, "refuse")
	if err := pingCallback(callbackPath{program: 0x40000000, addr: refuse.l.Addr().String()}); err == nil {
		t.Error("ping of a refusing path succeeded")
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()
	if err := pingCallback(callbackPath{addr: closedAddr}); err == nil {
		t.Error("ping of a closed port succeeded")
	}
}

// setClientIDCallback runs SETCLIENTID and SETCLIENTID_CONFIRM announcing the
// given callback service.
func setClientIDCallback(tc *testClient, name string, program uint32, netid, uaddr string) uint64 {
	tc.t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opSetClientID)
		e.OpaqueFixed([]byte("verify01"))
		e.Opaque([]byte(name))
		e.Uint32(program)
		e.String(netid)
		e.String(uaddr)
		e.Uint32(testCBIdent)
		return 1
	})
	if st != nfs4OK {
		tc.t.Fatalf("SETCLIENTID status = %d", st)
	}
	expectOp(tc.t, d, opSetClientID, nfs4OK)
	clientID := d.Uint64()
	confirm := d.OpaqueFixed(8)

	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opSetClientIDConfirm)
		e.Uint64(clientID)
		e.OpaqueFixed(confirm)
		return 1
	})
	if st != nfs4OK {
		tc.t.Fatalf("SETCLIENTID_CONFIRM status = %d", st)
	}
	expectOp(tc.t, d, opSetClientIDConfirm, nfs4OK)
	return clientID
}

func callbackState(s *Server, id uint64) (addr string, up bool) {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	c, ok := s.state.confirmed[id]
	if !ok {
		return "", false
	}
	return c.cb.addr, c.cbUp
}

func TestCallbackProbeRecordsAnswer(t *testing.T) {
	cb := startCBNullServer(t, 0x40000000, "answer")
	tc := newTestClient(t, testFS(t))
	id := setClientIDCallback(tc, "callback-client", 0x40000000, "tcp", cb.uaddr())

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, up := callbackState(tc.s, id); up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("callback path never recorded as answering")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCallbackUnusableAddressSkipsProbe(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	// The harness default: an unspecified address with port zero, which real
	// clients send when they run no callback service.
	id := setClientIDCallback(tc, "callback-client", 0x40000000, "tcp", "0.0.0.0.0.0")
	if addr, up := callbackState(tc.s, id); addr != "" || up {
		t.Fatalf("callback path = %q, up = %v, want none", addr, up)
	}
}

// TestCallbackStallDoesNotDelayConfirm is the M6a half of the requirement
// that an unreachable callback path slows nothing down: the probe must run
// off the request path, so SETCLIENTID_CONFIRM answers long before the probe
// times out against a peer that accepts and never replies.
func TestCallbackStallDoesNotDelayConfirm(t *testing.T) {
	cb := startCBNullServer(t, 0x40000000, "stall")
	tc := newTestClient(t, testFS(t))
	start := time.Now()
	id := setClientIDCallback(tc, "callback-client", 0x40000000, "tcp", cb.uaddr())
	if took := time.Since(start); took > callbackTimeout/2 {
		t.Fatalf("SETCLIENTID round trips took %v with a stalled callback path", took)
	}
	if _, up := callbackState(tc.s, id); up {
		t.Fatal("stalled callback path recorded as answering")
	}
}
