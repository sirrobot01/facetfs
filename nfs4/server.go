package nfs4

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirrobot01/facetfs"
)

const (
	defaultLease      = 90 * time.Second
	defaultMaxIO      = 1 << 20
	defaultDirEntries = 100_000
	// headroom covers RPC framing, compound overhead, and attribute bodies
	// around one maximum-size READ or WRITE.
	headroom = 96 << 10
)

// Server serves NFSv4.0 (RFC 7530) from a FileSystem. The zero value of every
// optional field is usable.
type Server struct {
	// FileSystem is the served filesystem. Required.
	//
	// Optional interfaces unlock protocol features: facetfs.SymlinkFS serves
	// READLINK, symlink CREATE, and symlink-aware attributes;
	// facetfs.SetStatFS serves SETATTR; facetfs.StatVFSFS serves space and
	// file-count attributes; facetfs.LinkFS serves LINK. A File with a
	// Sync() error method backs COMMIT and stable WRITE.
	FileSystem facetfs.FileSystem
	// HandleKey seals filehandles. Zero means a random key per Server, so
	// clients must remount after a restart.
	HandleKey []byte
	// LeaseDuration is the client lease. Zero means 90 seconds.
	LeaseDuration time.Duration
	// MaxReadBytes and MaxWriteBytes cap one READ or WRITE and are
	// advertised as the maxread and maxwrite attributes. Zero means 1 MiB.
	MaxReadBytes  uint32
	MaxWriteBytes uint32
	// MaxDirectoryEntries caps one directory listing. Zero means 100 000.
	MaxDirectoryEntries int
	// Logger, if set, receives per-connection faults from Serve.
	Logger func(error)

	initOnce  sync.Once
	initErr   error
	fh        *fhCodec
	verifier  [8]byte
	supported bitmap
	state     *stateStore
	dirs      *dirCache
	sweepMu   sync.Mutex
	sweepRefs int
	sweepStop chan struct{}
}

func (s *Server) init() error {
	s.initOnce.Do(func() {
		if s.FileSystem == nil {
			s.initErr = errors.New("nfs4: FileSystem is required")
			return
		}
		key := s.HandleKey
		if len(key) == 0 {
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				s.initErr = err
				return
			}
		}
		s.fh = newFHCodec(key)
		s.supported = s.supportedAttrs()
		s.state = newStateStore(s.lease())
		s.dirs = newDirCache(s.state.now, s.lease(), maxCachedDirEntries)
		if _, err := rand.Read(s.verifier[:]); err != nil {
			s.initErr = err
		}
	})
	return s.initErr
}

func (s *Server) lease() time.Duration {
	if s.LeaseDuration > 0 {
		return s.LeaseDuration
	}
	return defaultLease
}

func (s *Server) maxRead() uint32 {
	if s.MaxReadBytes > 0 {
		return s.MaxReadBytes
	}
	return defaultMaxIO
}

func (s *Server) maxWrite() uint32 {
	if s.MaxWriteBytes > 0 {
		return s.MaxWriteBytes
	}
	return defaultMaxIO
}

func (s *Server) maxDirEntries() int {
	if s.MaxDirectoryEntries > 0 {
		return s.MaxDirectoryEntries
	}
	return defaultDirEntries
}

func (s *Server) requestCap() int  { return int(s.maxWrite()) + headroom }
func (s *Server) responseCap() int { return int(s.maxRead()) + headroom }

// Serve accepts connections until ctx is canceled or the listener fails.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if err := s.init(); err != nil {
		return err
	}
	stopSweeper := s.startSweeper()
	defer stopSweeper()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-done:
		}
	}()

	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		conns.Go(func() {
			if err := s.serveConn(ctx, c); err != nil && ctx.Err() == nil && s.Logger != nil {
				s.Logger(err)
			}
		})
	}
}

// ServeConn serves one connection until the client disconnects or ctx is
// canceled. It returns nil on a clean client disconnect.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) error {
	if err := s.init(); err != nil {
		return err
	}
	stopSweeper := s.startSweeper()
	defer stopSweeper()
	return s.serveConn(ctx, c)
}
