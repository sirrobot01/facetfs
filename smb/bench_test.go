package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
)

// newBenchClient is an authenticated, signing session over TCP loopback. The
// connection and the session are established before the timer starts, so a
// benchmark measures steady-state protocol cost, including client framing
// and loopback I/O, and not connection setup.
func newBenchClient(b *testing.B, fsys facetfs.FileSystem, dialect uint16) *authClient {
	b.Helper()
	hash := NTHash("correct horse battery staple")
	s := &Server{FileSystem: fsys, Authenticator: passwordAuth{hashes: map[string][]byte{"DOMAIN\\alice": hash}}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		s.Serve(ctx, listener)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		cancel()
		listener.Close()
		b.Fatal(err)
	}
	b.Cleanup(func() {
		conn.Close()
		cancel()
		listener.Close()
		<-served
	})
	conn.SetDeadline(time.Now().Add(10 * time.Minute))
	tc := &testClient{t: b, c: conn, s: s}
	if dialect == dialect311 {
		return auth311(tc, hash)
	}
	return auth210(tc, hash)
}

// exchangeCharged is exchange with an explicit credit charge, which a read
// or write above 64 KiB must carry.
func (ac *authClient) exchangeCharged(command, charge uint16, body []byte) (header, []byte) {
	ac.t.Helper()
	req := ac.request(command, body)
	binary.LittleEndian.PutUint16(req[6:], charge)
	if charge > 1 {
		ac.id += uint64(charge - 1)
	}
	binary.LittleEndian.PutUint32(req[36:], ac.tree)
	binary.LittleEndian.PutUint64(req[40:], ac.session)
	if !signMessage(ac.key, ac.alg, req) {
		ac.t.Fatal("sign request")
	}
	ac.send(req)
	frame, err := readFrame(ac.c, 2<<20)
	if err != nil {
		ac.t.Fatal(err)
	}
	h, ok := decodeHeader(frame)
	if !ok {
		ac.t.Fatal("response header")
	}
	return h, frame[headerSize:]
}

func seededBenchFS(b *testing.B, size int) facetfs.FileSystem {
	b.Helper()
	fsys := facetfs.NewMemFS()
	f, err := fsys.OpenFile(context.Background(), "/data", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.Write(make([]byte, size)); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	return fsys
}

func creditCharge(size int) uint16 {
	return uint16(max((size+65535)/65536, 1))
}

func byteSizeName(size int) string {
	switch size {
	case 4 << 10:
		return "4KiB"
	case 64 << 10:
		return "64KiB"
	case 1 << 20:
		return "1MiB"
	default:
		return fmt.Sprintf("%dB", size)
	}
}

// benchStat is one protocol-native metadata lookup. SMB has no path-based
// stat: the native form is a CREATE and a CLOSE that reports the attributes.
func benchStat(ac *authClient) {
	h, body := ac.exchange(cmdCreate, createRequest("data", fileOpen, 0))
	id := responseFileID(ac.t, h, body)
	req := closeRequest(id)
	binary.LittleEndian.PutUint16(req[2:], 1) // report the final attributes
	if h, _ := ac.exchange(cmdClose, req); h.status != statusSuccess {
		ac.t.Fatalf("CLOSE = %#x", h.status)
	}
}

// benchRead opens, transfers, and closes the complete file, the way the
// other protocol packages' comparison benchmark defines a read.
func benchRead(ac *authClient, dst []byte) {
	h, body := ac.exchange(cmdCreate, createRequest("data", fileOpen, fileNonDirectoryFile))
	id := responseFileID(ac.t, h, body)
	req := make([]byte, 48)
	binary.LittleEndian.PutUint16(req, 49)
	binary.LittleEndian.PutUint32(req[4:], uint32(len(dst)))
	copy(req[16:], id[:])
	h, body = ac.exchangeCharged(cmdRead, creditCharge(len(dst)), req)
	if h.status != statusSuccess || len(body) < 16 {
		ac.t.Fatalf("READ = %#x", h.status)
	}
	if got := copy(dst, body[16:]); got != len(dst) {
		ac.t.Fatalf("read %d bytes, want %d", got, len(dst))
	}
	if h, _ := ac.exchange(cmdClose, closeRequest(id)); h.status != statusSuccess {
		ac.t.Fatalf("CLOSE = %#x", h.status)
	}
}

// benchWrite truncates, transfers, and closes the complete file.
func benchWrite(ac *authClient, src []byte) {
	h, body := ac.exchange(cmdCreate, createRequest("data", fileOverwriteIf, fileNonDirectoryFile))
	id := responseFileID(ac.t, h, body)
	req := make([]byte, 48)
	binary.LittleEndian.PutUint16(req, 49)
	binary.LittleEndian.PutUint16(req[2:], headerSize+48)
	binary.LittleEndian.PutUint32(req[4:], uint32(len(src)))
	copy(req[16:], id[:])
	h, _ = ac.exchangeCharged(cmdWrite, creditCharge(len(src)), append(req, src...))
	if h.status != statusSuccess {
		ac.t.Fatalf("WRITE = %#x", h.status)
	}
	if h, _ := ac.exchange(cmdClose, closeRequest(id)); h.status != statusSuccess {
		ac.t.Fatalf("CLOSE = %#x", h.status)
	}
}

// BenchmarkSignedSession measures user-visible operations of one signed
// session against an in-memory FileSystem, mirroring the cross-protocol
// comparison in the nfs4 package:
//
//   - Echo is one signed round trip, under each signing algorithm.
//   - Stat is one protocol-native metadata lookup.
//   - Read opens, transfers, and closes the complete file.
//   - Write truncates, transfers, and closes the complete file.
func BenchmarkSignedSession(b *testing.B) {
	b.Run("Echo/HMAC-SHA256", func(b *testing.B) {
		ac := newBenchClient(b, seededBenchFS(b, 1), dialect210)
		b.ReportAllocs()
		for b.Loop() {
			if h, _ := ac.exchange(cmdEcho, echoRequest()); h.status != statusSuccess {
				b.Fatalf("ECHO = %#x", h.status)
			}
		}
	})
	b.Run("Echo/AES-CMAC", func(b *testing.B) {
		ac := newBenchClient(b, seededBenchFS(b, 1), dialect311)
		b.ReportAllocs()
		for b.Loop() {
			if h, _ := ac.exchange(cmdEcho, echoRequest()); h.status != statusSuccess {
				b.Fatalf("ECHO = %#x", h.status)
			}
		}
	})
	b.Run("Stat", func(b *testing.B) {
		ac := newBenchClient(b, seededBenchFS(b, 1), dialect311)
		benchStat(ac)
		b.ReportAllocs()
		for b.Loop() {
			benchStat(ac)
		}
	})
	for _, size := range []int{4 << 10, 64 << 10, 1 << 20} {
		b.Run("Read/"+byteSizeName(size), func(b *testing.B) {
			ac := newBenchClient(b, seededBenchFS(b, size), dialect311)
			dst := make([]byte, size)
			benchRead(ac, dst)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				benchRead(ac, dst)
			}
		})
		b.Run("Write/"+byteSizeName(size), func(b *testing.B) {
			ac := newBenchClient(b, seededBenchFS(b, size), dialect311)
			src := bytes.Repeat([]byte{0xa5}, size)
			benchWrite(ac, src)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				benchWrite(ac, src)
			}
		})
	}
}
