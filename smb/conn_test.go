package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
)

// stubAuth stands in for a credential store in transport-only tests.
type stubAuth struct{}

func (stubAuth) NTHash(ctx context.Context, domain, user string) ([]byte, error) {
	return nil, errors.New("no such user")
}

// testClient drives the server with raw frames.
type testClient struct {
	t  testing.TB
	c  net.Conn
	s  *Server
	id uint64
}

func newTestClient(t testing.TB) *testClient {
	t.Helper()
	return newTestClientFor(t, &Server{FileSystem: facetfs.NewMemFS(), Authenticator: stubAuth{}})
}

func newTestClientFor(t testing.TB, s *Server) *testClient {
	t.Helper()
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(ctx, server) }()
	t.Cleanup(func() {
		client.Close()
		cancel()
		<-done
	})
	client.SetDeadline(time.Now().Add(10 * time.Second))
	return &testClient{t: t, c: client, s: s}
}

// request builds one message: a header with the next message id, and body.
func (tc *testClient) request(command uint16, body []byte) []byte {
	tc.id++
	h := header{
		command:   command,
		credits:   32,
		messageID: tc.id - 1,
	}
	return append(h.encode(), body...)
}

func (tc *testClient) send(frame []byte) {
	tc.t.Helper()
	if err := writeFrame(tc.c, frame); err != nil {
		tc.t.Fatal(err)
	}
}

// sendRejected sends a frame the server is expected to refuse. The write
// itself may fail, because the server may close the connection before the
// whole frame is read.
func (tc *testClient) sendRejected(frame []byte) {
	tc.t.Helper()
	writeFrame(tc.c, frame)
}

// recv reads one reply frame and returns its first message.
func (tc *testClient) recv() (header, []byte) {
	tc.t.Helper()
	frame, err := readFrame(tc.c, 1<<20)
	if err != nil {
		tc.t.Fatalf("read reply: %v", err)
	}
	h, ok := decodeHeader(frame)
	if !ok {
		tc.t.Fatal("reply header did not decode")
	}
	end := len(frame)
	if h.nextCommand != 0 {
		end = int(h.nextCommand)
	}
	return h, frame[headerSize:end]
}

// negotiateRequest builds a NEGOTIATE offering the named dialects. When 3.1.1
// is offered it carries the contexts that dialect requires.
func negotiateRequest(dialects []uint16, contexts bool) []byte {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b[0:], 36)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(b[4:], signingEnabled)
	for _, d := range dialects {
		b = binary.LittleEndian.AppendUint16(b, d)
	}
	if !contexts {
		return b
	}
	for (headerSize+len(b))%8 != 0 {
		b = append(b, 0)
	}
	binary.LittleEndian.PutUint32(b[28:], uint32(headerSize+len(b)))
	binary.LittleEndian.PutUint16(b[32:], 2)

	preauth := make([]byte, 6)
	binary.LittleEndian.PutUint16(preauth[0:], 1)
	binary.LittleEndian.PutUint16(preauth[2:], 4)
	binary.LittleEndian.PutUint16(preauth[4:], hashSHA512)
	preauth = append(preauth, 1, 2, 3, 4)
	b = appendContext(b, contextPreauthIntegrity, preauth)

	signing := make([]byte, 4)
	binary.LittleEndian.PutUint16(signing[0:], 1)
	binary.LittleEndian.PutUint16(signing[2:], signAESCMAC)
	return appendContext(b, contextSigning, signing)
}

func (tc *testClient) negotiate(dialects []uint16, contexts bool) (header, []byte) {
	tc.t.Helper()
	tc.send(tc.request(cmdNegotiate, negotiateRequest(dialects, contexts)))
	return tc.recv()
}

func echoRequest() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:], 4)
	return b
}

func TestEchoAfterNegotiate(t *testing.T) {
	tc := newTestClient(t)
	if h, _ := tc.negotiate([]uint16{dialect311, dialect210}, true); h.status != statusSuccess {
		t.Fatalf("NEGOTIATE status = %#x", h.status)
	}
	tc.send(tc.request(cmdEcho, echoRequest()))
	h, body := tc.recv()
	if h.status != statusSuccess {
		t.Fatalf("ECHO status = %#x", h.status)
	}
	if h.command != cmdEcho || h.flags&flagServerToRedir == 0 {
		t.Fatalf("ECHO reply header = %+v", h)
	}
	if len(body) < 4 || binary.LittleEndian.Uint16(body) != 4 {
		t.Fatalf("ECHO body = %x", body)
	}
}

func TestCommandBeforeNegotiateIsRefused(t *testing.T) {
	tc := newTestClient(t)
	tc.send(tc.request(cmdEcho, echoRequest()))
	if h, _ := tc.recv(); h.status != statusInvalidParameter {
		t.Fatalf("ECHO before NEGOTIATE = %#x, want STATUS_INVALID_PARAMETER", h.status)
	}
}

func TestSecondNegotiateIsRefused(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)
	tc.send(tc.request(cmdNegotiate, negotiateRequest([]uint16{dialect210}, false)))
	if h, _ := tc.recv(); h.status != statusInvalidParameter {
		t.Fatalf("second NEGOTIATE = %#x, want STATUS_INVALID_PARAMETER", h.status)
	}
}

func TestTreeConnectRequiresAuthenticatedSession(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)
	tc.send(tc.request(cmdTreeConnect, make([]byte, 8)))
	h, body := tc.recv()
	if h.status != statusUserSessionDeleted {
		t.Fatalf("TREE_CONNECT = %#x, want STATUS_USER_SESSION_DELETED", h.status)
	}
	// A failed command carries the error structure, not an empty body.
	if len(body) != 9 || binary.LittleEndian.Uint16(body) != 9 {
		t.Fatalf("error body = %x", body)
	}
}

func TestUnknownCommandIsNotSupported(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)
	tc.send(tc.request(0x00FF, nil))
	if h, _ := tc.recv(); h.status != statusNotSupported {
		t.Fatalf("unknown command = %#x, want STATUS_NOT_SUPPORTED", h.status)
	}
}

func TestCompoundChainAnswersEveryMessage(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)

	first := tc.request(cmdEcho, echoRequest())
	for len(first)%8 != 0 {
		first = append(first, 0)
	}
	binary.LittleEndian.PutUint32(first[20:], uint32(len(first)))
	second := tc.request(cmdEcho, echoRequest())
	// The second message is related, so it inherits the session and tree of
	// the first rather than carrying its own.
	binary.LittleEndian.PutUint32(second[16:], flagRelatedOps)
	tc.send(append(first, second...))

	frame, err := readFrame(tc.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	h1, ok := decodeHeader(frame)
	if !ok || h1.status != statusSuccess {
		t.Fatalf("first reply = %+v", h1)
	}
	if h1.nextCommand == 0 {
		t.Fatal("first reply does not chain to the second")
	}
	if h1.nextCommand%8 != 0 {
		t.Fatalf("chained reply is not 8-byte aligned: %d", h1.nextCommand)
	}
	h2, ok := decodeHeader(frame[h1.nextCommand:])
	if !ok || h2.status != statusSuccess {
		t.Fatalf("second reply = %+v", h2)
	}
	if h2.nextCommand != 0 {
		t.Fatal("second reply chains onward")
	}
	if h1.messageID == h2.messageID {
		t.Fatal("both replies carry one message id")
	}
}

func TestChainFailurePoisonsRelatedMessagesOnly(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)

	// The first message fails on its structure size. The related message
	// after it must fail with the same status without running; the unrelated
	// third message must still run.
	first := tc.request(cmdEcho, make([]byte, 4))
	for len(first)%8 != 0 {
		first = append(first, 0)
	}
	binary.LittleEndian.PutUint32(first[20:], uint32(len(first)))
	second := tc.request(cmdEcho, echoRequest())
	binary.LittleEndian.PutUint32(second[16:], flagRelatedOps)
	for len(second)%8 != 0 {
		second = append(second, 0)
	}
	binary.LittleEndian.PutUint32(second[20:], uint32(len(second)))
	third := tc.request(cmdEcho, echoRequest())
	tc.send(append(append(first, second...), third...))

	frame, err := readFrame(tc.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	h1, ok := decodeHeader(frame)
	if !ok || h1.status != statusInvalidParameter || h1.nextCommand == 0 {
		t.Fatalf("first reply = %+v", h1)
	}
	h2, ok := decodeHeader(frame[h1.nextCommand:])
	if !ok || h2.status != statusInvalidParameter || h2.nextCommand == 0 {
		t.Fatalf("related reply after a failure = %+v", h2)
	}
	h3, ok := decodeHeader(frame[h1.nextCommand+h2.nextCommand:])
	if !ok || h3.status != statusSuccess {
		t.Fatalf("unrelated reply after a failure = %+v", h3)
	}
}

func TestRelatedMessageMayNotStartAChain(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)
	frame := tc.request(cmdEcho, echoRequest())
	binary.LittleEndian.PutUint32(frame[16:], flagRelatedOps)
	tc.sendRejected(frame)
	if _, err := readFrame(tc.c, 1<<20); err == nil {
		t.Fatal("a chain starting with a related message was answered")
	}
}

func TestReplayedMessageIDEndsTheConnection(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)
	replay := tc.request(cmdEcho, echoRequest())
	tc.send(replay)
	if h, _ := tc.recv(); h.status != statusSuccess {
		t.Fatalf("ECHO status = %#x", h.status)
	}
	tc.sendRejected(replay)
	if _, err := readFrame(tc.c, 1<<20); err == nil {
		t.Fatal("a replayed message id was answered")
	}
}

func TestCreditsAreAlwaysGranted(t *testing.T) {
	tc := newTestClient(t)
	h, _ := tc.negotiate([]uint16{dialect210}, false)
	if h.credits == 0 {
		t.Fatal("NEGOTIATE granted no credits, so the client would stall")
	}
	// Ask for none: the server must still grant one.
	frame := tc.request(cmdEcho, echoRequest())
	binary.LittleEndian.PutUint16(frame[14:], 0)
	tc.send(frame)
	if h, _ := tc.recv(); h.credits < 1 {
		t.Fatalf("granted %d credits for a request that asked for none", h.credits)
	}
}

func TestOverchargingCreditsEndsTheConnection(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)
	frame := tc.request(cmdEcho, echoRequest())
	// One credit charge above what any response has granted.
	binary.LittleEndian.PutUint16(frame[6:], maxCredits+1)
	tc.sendRejected(frame)
	if _, err := readFrame(tc.c, 1<<20); err == nil {
		t.Fatal("a request charging more credits than it held was answered")
	}
}

func TestSMB1IsRefused(t *testing.T) {
	tc := newTestClient(t)
	frame := append([]byte{0xFF, 'S', 'M', 'B'}, make([]byte, 60)...)
	tc.sendRejected(frame)
	tc.expectSMB1Refusal()
}

// expectSMB1Refusal reads the STATUS_NOT_SUPPORTED answer to an SMB1 message
// and then the close of the connection.
func (tc *testClient) expectSMB1Refusal() {
	tc.t.Helper()
	reply, err := readFrame(tc.c, 1<<20)
	if err != nil {
		tc.t.Fatalf("SMB1 refusal: %v", err)
	}
	h, ok := decodeHeader(reply)
	if !ok || h.status != statusNotSupported {
		tc.t.Fatalf("SMB1 refusal = %+v, decoded %v", h, ok)
	}
	if _, err := readFrame(tc.c, 1<<20); err == nil {
		tc.t.Fatal("connection remained open after SMB1 refusal")
	}
}

// smb1NegotiateFrame builds an SMB1 NEGOTIATE offering the named dialect
// strings, the way a multi-protocol client opens a connection.
func smb1NegotiateFrame(dialects ...string) []byte {
	frame := make([]byte, smb1HeaderSize)
	copy(frame, smb1ProtocolID[:])
	frame[4] = smb1CmdNegotiate
	frame = append(frame, 0) // word count
	var data []byte
	for _, d := range dialects {
		data = append(data, 0x02)
		data = append(data, d...)
		data = append(data, 0)
	}
	frame = binary.LittleEndian.AppendUint16(frame, uint16(len(data)))
	return append(frame, data...)
}

func TestSMB1MultiProtocolNegotiateStepsUpToSMB2(t *testing.T) {
	tc := newTestClient(t)
	tc.send(smb1NegotiateFrame("NT LM 0.12", "SMB 2.002", "SMB 2.???"))
	h, body := tc.recv()
	if h.command != cmdNegotiate || h.status != statusSuccess || h.messageID != 0 {
		t.Fatalf("step-up reply header = %+v", h)
	}
	if h.credits == 0 {
		t.Fatal("step-up granted no credits, so the client would stall")
	}
	if got := binary.LittleEndian.Uint16(body[4:]); got != dialectSMB2Wildcard {
		t.Fatalf("step-up dialect = %#x, want the SMB2 wildcard", got)
	}

	// The client now negotiates again in SMB2, and the connection works.
	if h, _ := tc.negotiate([]uint16{dialect311, dialect210}, true); h.status != statusSuccess {
		t.Fatalf("NEGOTIATE after step-up = %#x", h.status)
	}
	tc.send(tc.request(cmdEcho, echoRequest()))
	if h, _ := tc.recv(); h.status != statusSuccess {
		t.Fatalf("ECHO after step-up = %#x", h.status)
	}
}

func TestSMB1WithoutSMB2DialectIsRefused(t *testing.T) {
	tc := newTestClient(t)
	tc.sendRejected(smb1NegotiateFrame("NT LM 0.12"))
	tc.expectSMB1Refusal()
}

func TestSecondSMB1NegotiateIsRefused(t *testing.T) {
	tc := newTestClient(t)
	tc.send(smb1NegotiateFrame("SMB 2.???"))
	if h, _ := tc.recv(); h.status != statusSuccess {
		t.Fatalf("step-up = %#x", h.status)
	}
	tc.sendRejected(smb1NegotiateFrame("SMB 2.???"))
	tc.expectSMB1Refusal()
}

func TestSMB1AfterNegotiateIsRefused(t *testing.T) {
	tc := newTestClient(t)
	tc.negotiate([]uint16{dialect210}, false)
	tc.sendRejected(smb1NegotiateFrame("SMB 2.???"))
	tc.expectSMB1Refusal()
}

func TestMalformedFramesEndTheConnection(t *testing.T) {
	tests := []struct {
		name  string
		frame func(tc *testClient) []byte
	}{
		{"short header", func(*testClient) []byte { return make([]byte, headerSize-1) }},
		{"bad protocol id", func(*testClient) []byte { return make([]byte, headerSize) }},
		{"bad structure size", func(tc *testClient) []byte {
			f := tc.request(cmdEcho, echoRequest())
			binary.LittleEndian.PutUint16(f[4:], 32)
			return f
		}},
		{"next command not aligned", func(tc *testClient) []byte {
			f := tc.request(cmdEcho, echoRequest())
			binary.LittleEndian.PutUint32(f[20:], 65)
			return f
		}},
		{"next command past the frame", func(tc *testClient) []byte {
			f := tc.request(cmdEcho, echoRequest())
			binary.LittleEndian.PutUint32(f[20:], 4096)
			return f
		}},
		{"next command inside the header", func(tc *testClient) []byte {
			f := tc.request(cmdEcho, echoRequest())
			binary.LittleEndian.PutUint32(f[20:], 8)
			return f
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestClient(t)
			tc.negotiate([]uint16{dialect210}, false)
			tc.sendRejected(tt.frame(tc))
			if _, err := readFrame(tc.c, 1<<20); err == nil {
				t.Fatal("a malformed frame was answered")
			}
		})
	}
}

func TestTransportFrameBounds(t *testing.T) {
	// The prefix must start with a zero byte.
	if _, err := readFrame(newPipeReader(t, []byte{1, 0, 0, 64}), 1<<20); err == nil {
		t.Fatal("a frame with a non-zero prefix byte was accepted")
	}
	// A frame smaller than a header cannot hold one.
	if _, err := readFrame(newPipeReader(t, []byte{0, 0, 0, 8}), 1<<20); err == nil {
		t.Fatal("a frame shorter than the header was accepted")
	}
	// A frame above the cap ends the connection rather than allocating.
	if _, err := readFrame(newPipeReader(t, []byte{0, 0xFF, 0xFF, 0xFF}), 1<<16); err == nil {
		t.Fatal("an oversized frame was accepted")
	}
}

func newPipeReader(t *testing.T, data []byte) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	go func() {
		client.Write(data)
		client.Close()
	}()
	server.SetDeadline(time.Now().Add(5 * time.Second))
	return server
}

func TestServerRequiresFileSystemAndAuthenticator(t *testing.T) {
	if err := (&Server{Authenticator: stubAuth{}}).init(); err == nil {
		t.Fatal("a Server without a FileSystem started")
	}
	if err := (&Server{FileSystem: facetfs.NewMemFS()}).init(); err == nil {
		t.Fatal("a Server without an Authenticator started")
	}
}

func TestMessageWindowRefusesReplayAndDistantIDs(t *testing.T) {
	var w messageWindow
	if !w.take(0) || !w.take(1) {
		t.Fatal("the first ids were refused")
	}
	if w.take(0) {
		t.Fatal("a replayed id was accepted")
	}
	if !w.take(5) {
		t.Fatal("an id inside the window was refused")
	}
	if w.take(5) {
		t.Fatal("a replayed out-of-order id was accepted")
	}
	if w.take(uint64(len(w.used)) + 10) {
		t.Fatal("an id beyond the window was accepted")
	}
	// Filling the gap advances the window past everything consumed.
	for id := uint64(2); id <= 4; id++ {
		if !w.take(id) {
			t.Fatalf("id %d was refused", id)
		}
	}
	if w.base != 6 {
		t.Fatalf("window base = %d, want 6", w.base)
	}
	if w.take(3) {
		t.Fatal("an id below the window base was accepted")
	}
}
