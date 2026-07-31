package nfs4

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	clientsftp "github.com/pkg/sftp"
	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
	facetsftp "github.com/sirrobot01/facetfs/sftp"
	facetwebdav "github.com/sirrobot01/facetfs/webdav"
)

// protocolBench is a warm, already-connected client/server pair. The
// comparison deliberately excludes SSH and TLS: FacetFS owns neither of
// those transports, and including them would benchmark an application's
// authentication and cipher choices rather than these protocol packages.
type protocolBench interface {
	stat() error
	read([]byte) (int, error)
	write([]byte) (int, error)
}

type protocolBenchFactory struct {
	name string
	new  func(*testing.B, facetfs.FileSystem, int) protocolBench
}

var protocolBenchFactories = []protocolBenchFactory{
	{name: "NFSv4", new: newNFSProtocolBench},
	{name: "SFTP", new: newSFTPProtocolBench},
	{name: "WebDAV", new: newWebDAVProtocolBench},
}

// BenchmarkProtocolComparison measures equivalent user-visible operations
// through each protocol against the same in-memory FileSystem:
//
//   - Stat is one protocol-native metadata lookup.
//   - Read opens, transfers, and closes the complete file.
//   - Write truncates, transfers, and closes the complete file.
//
// Connections and sessions are established before the timer starts. The
// benchmark therefore measures steady-state protocol cost, including client
// framing and loopback I/O, without mixing connection setup into every file
// operation.
func BenchmarkProtocolComparison(b *testing.B) {
	b.Run("Stat", func(b *testing.B) {
		for _, factory := range protocolBenchFactories {
			b.Run(factory.name, func(b *testing.B) {
				bench := factory.new(b, seededBenchFS(b, 1), 1)
				if err := bench.stat(); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if err := bench.stat(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})

	for _, size := range []int{4 << 10, 64 << 10, 1 << 20} {
		name := byteSizeName(size)
		b.Run("Read/"+name, func(b *testing.B) {
			for _, factory := range protocolBenchFactories {
				b.Run(factory.name, func(b *testing.B) {
					bench := factory.new(b, seededBenchFS(b, size), size)
					if err := bench.stat(); err != nil {
						b.Fatal(err)
					}
					dst := make([]byte, size)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					for b.Loop() {
						n, err := bench.read(dst)
						if err != nil {
							b.Fatal(err)
						}
						if n != size {
							b.Fatalf("read %d bytes, want %d", n, size)
						}
					}
				})
			}
		})

		b.Run("Write/"+name, func(b *testing.B) {
			for _, factory := range protocolBenchFactories {
				b.Run(factory.name, func(b *testing.B) {
					bench := factory.new(b, seededBenchFS(b, size), size)
					if err := bench.stat(); err != nil {
						b.Fatal(err)
					}
					src := bytes.Repeat([]byte{0xa5}, size)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					for b.Loop() {
						n, err := bench.write(src)
						if err != nil {
							b.Fatal(err)
						}
						if n != size {
							b.Fatalf("wrote %d bytes, want %d", n, size)
						}
					}
				})
			}
		})
	}
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

type nfsProtocolBench struct {
	conn *benchConn
	size int
}

func newNFSProtocolBench(b *testing.B, fsys facetfs.FileSystem, size int) protocolBench {
	b.Helper()
	p := &nfsProtocolBench{conn: newBenchConn(b, fsys), size: size}
	return p
}

func nfsProtocolStatRecord() []byte {
	var attrs bitmap
	for _, n := range []int{attrType, attrSize, attrChange, attrFileID, attrMode, attrTimeModify} {
		attrs.set(n)
	}
	return benchRecord(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")
		e.Uint32(opGetAttr)
		encodeBitmap(e, attrs)
		return 3
	})
}

func nfsProtocolReadRecord(size int) []byte {
	return benchRecord(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")
		e.Uint32(opRead)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(uint32(size))
		return 3
	})
}

func nfsProtocolWriteRecord(payload []byte) []byte {
	return benchRecord(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")

		// NFS WRITE does not truncate by itself. SETATTR size=0 in the same
		// compound gives it the same replace-file semantics as WebDAV PUT and
		// an SFTP open with O_TRUNC.
		e.Uint32(opSetAttr)
		encodeStateid(e, 0, [12]byte{})
		var mask bitmap
		mask.set(attrSize)
		encodeBitmap(e, mask)
		var values xdr.Encoder
		values.Uint64(0)
		e.Opaque(values.Bytes())

		e.Uint32(opWrite)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(unstable4)
		e.Opaque(payload)
		return 4
	})
}

func (p *nfsProtocolBench) stat() error {
	d := p.conn.roundTripBench(nfsProtocolStatRecord())
	return compoundBenchError(d)
}

func (p *nfsProtocolBench) read(dst []byte) (int, error) {
	d := p.conn.roundTripBench(nfsProtocolReadRecord(p.size))
	if err := compoundBenchError(d); err != nil {
		return 0, err
	}
	data, err := nfsReadResult(d, uint32(len(dst)))
	if err != nil {
		return 0, err
	}
	return copy(dst, data), nil
}

func (p *nfsProtocolBench) write(src []byte) (int, error) {
	d := p.conn.roundTripBench(nfsProtocolWriteRecord(src))
	if err := compoundBenchError(d); err != nil {
		return 0, err
	}
	return len(src), nil
}

// roundTripBench is the non-testing.B form used behind the shared benchmark
// interface. Errors are returned through a decoder so the timed methods can
// share the same signature as the other protocol clients.
func (bc *benchConn) roundTripBench(record []byte) *xdr.Decoder {
	if err := writeRecord(bc.conn, record); err != nil {
		d := xdr.NewDecoder(nil)
		d.Fail(err)
		return d
	}
	reply, err := readRecord(bc.conn, 1<<24)
	if err != nil {
		d := xdr.NewDecoder(nil)
		d.Fail(err)
		return d
	}
	return xdr.NewDecoder(reply)
}

func compoundBenchError(d *xdr.Decoder) error {
	d.Uint32() // xid
	d.Uint32() // message type
	d.Uint32() // accepted/denied
	d.Uint32() // verifier flavor
	d.Opaque(maxCredBytes)
	if accepted := d.Uint32(); accepted != acceptSuccess {
		return fmt.Errorf("NFS RPC accept status %d", accepted)
	}
	if status := nfsStat(d.Uint32()); status != nfs4OK {
		return fmt.Errorf("NFS compound status %d", status)
	}
	return d.Err()
}

func nfsReadResult(d *xdr.Decoder, limit uint32) ([]byte, error) {
	d.Opaque(maxTagBytes)
	if count := d.Uint32(); count != 3 {
		return nil, fmt.Errorf("NFS result count %d, want 3", count)
	}
	for _, operation := range []uint32{opPutRootFH, opLookup, opRead} {
		if got := d.Uint32(); got != operation {
			return nil, fmt.Errorf("NFS result operation %d, want %d", got, operation)
		}
		if status := nfsStat(d.Uint32()); status != nfs4OK {
			return nil, fmt.Errorf("NFS operation %d status %d", operation, status)
		}
	}
	d.Bool() // eof
	data := d.Opaque(limit)
	if err := d.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

type sftpProtocolBench struct {
	client *clientsftp.Client
}

func newSFTPProtocolBench(b *testing.B, fsys facetfs.FileSystem, _ int) protocolBench {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = (&facetsftp.Server{FileSystem: fsys}).Serve(ctx, conn)
		}
		done <- err
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		cancel()
		_ = listener.Close()
		b.Fatal(err)
	}
	client, err := clientsftp.NewClientPipe(conn, conn)
	if err != nil {
		cancel()
		_ = conn.Close()
		_ = listener.Close()
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = client.Close()
		cancel()
		_ = listener.Close()
		<-done
	})
	return &sftpProtocolBench{client: client}
}

func (p *sftpProtocolBench) stat() error {
	_, err := p.client.Stat("/data")
	return err
}

func (p *sftpProtocolBench) read(dst []byte) (int, error) {
	f, err := p.client.Open("/data")
	if err != nil {
		return 0, err
	}
	n, err := io.ReadFull(f, dst)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return n, err
}

func (p *sftpProtocolBench) write(src []byte) (int, error) {
	f, err := p.client.OpenFile("/data", os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return 0, err
	}
	n, err := f.Write(src)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return n, err
}

type webDAVProtocolBench struct {
	client *http.Client
	url    string
}

func newWebDAVProtocolBench(b *testing.B, fsys facetfs.FileSystem, _ int) protocolBench {
	b.Helper()
	server := httptest.NewServer(&facetwebdav.Handler{FileSystem: fsys})
	b.Cleanup(server.Close)
	return &webDAVProtocolBench{client: server.Client(), url: server.URL + "/data"}
}

func (p *webDAVProtocolBench) stat() error {
	request, err := http.NewRequest("PROPFIND", p.url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Depth", "0")
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusMultiStatus {
		return fmt.Errorf("WebDAV PROPFIND status %s", response.Status)
	}
	if readErr != nil {
		return readErr
	}
	return closeErr
}

func (p *webDAVProtocolBench) read(dst []byte) (int, error) {
	response, err := p.client.Get(p.url)
	if err != nil {
		return 0, err
	}
	n, err := io.ReadFull(response.Body, dst)
	if closeErr := response.Body.Close(); err == nil {
		err = closeErr
	}
	if response.StatusCode != http.StatusOK {
		return n, fmt.Errorf("WebDAV GET status %s", response.Status)
	}
	return n, err
}

func (p *webDAVProtocolBench) write(src []byte) (int, error) {
	request, err := http.NewRequest(http.MethodPut, p.url, bytes.NewReader(src))
	if err != nil {
		return 0, err
	}
	response, err := p.client.Do(request)
	if err != nil {
		return 0, err
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return 0, fmt.Errorf("WebDAV PUT status %s", response.Status)
	}
	if readErr != nil {
		return 0, readErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	return len(src), nil
}
