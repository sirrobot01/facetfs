package smb

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
	defaultMaxIO      = 1 << 20
	defaultDirEntries = 100_000
	defaultShareName  = "share"
	defaultServerName = "FACETFS"
)

// Authenticator supplies the secret for one user.
//
// SMB derives the key that signs every message from the authentication
// exchange, so the package must run that exchange itself. The split is
// therefore drawn one level lower than in the other packages: the
// application owns the credential store and answers one question, and the
// package owns the protocol.
//
// NTHash returns MD4(UTF-16LE(password)) for the named user. An unknown user
// must return an error. The value is password-equivalent: store it as
// carefully as a password, and use it for nothing else.
type Authenticator interface {
	NTHash(ctx context.Context, domain, user string) ([]byte, error)
}

// Server serves SMB2 and SMB3 from a FileSystem. The zero value of every
// optional field is usable.
type Server struct {
	// FileSystem is the served filesystem. Required.
	FileSystem facetfs.FileSystem
	// Authenticator supplies the secret for a user. Required: this server
	// grants no anonymous access.
	Authenticator Authenticator
	// ShareName is the single share this Server exports. Zero means "share".
	ShareName string
	// ServerName is reported during authentication. Zero means "FACETFS".
	ServerName string
	// MaxReadBytes, MaxWriteBytes, and MaxTransactBytes cap one operation and
	// are advertised during negotiation. Zero means 1 MiB.
	MaxReadBytes     uint32
	MaxWriteBytes    uint32
	MaxTransactBytes uint32
	// MaxDirectoryEntries caps one directory listing. Zero means 100 000.
	MaxDirectoryEntries int
	// RequireSigning refuses a session that will not sign. The server signs
	// whenever the client asks for it either way.
	RequireSigning bool
	// Logger, if set, receives per-connection faults from Serve.
	Logger func(error)

	initOnce  sync.Once
	initErr   error
	guid      [16]byte
	startedAt time.Time
	state     *serverState
}

func (s *Server) init() error {
	s.initOnce.Do(func() {
		switch {
		case s.FileSystem == nil:
			s.initErr = errors.New("smb: FileSystem is required")
			return
		case s.Authenticator == nil:
			s.initErr = errors.New("smb: Authenticator is required")
			return
		}
		if _, err := rand.Read(s.guid[:]); err != nil {
			s.initErr = err
			return
		}
		s.startedAt = time.Now()
		s.state = newServerState(s)
	})
	return s.initErr
}

func (s *Server) maxRead() uint32 {
	if s.MaxReadBytes > 0 {
		return min(s.MaxReadBytes, maxFrameBytes-frameHeadroom)
	}
	return defaultMaxIO
}

func (s *Server) maxWrite() uint32 {
	if s.MaxWriteBytes > 0 {
		return min(s.MaxWriteBytes, maxFrameBytes-frameHeadroom)
	}
	return defaultMaxIO
}

func (s *Server) maxTransact() uint32 {
	if s.MaxTransactBytes > 0 {
		return min(s.MaxTransactBytes, maxFrameBytes-frameHeadroom)
	}
	return defaultMaxIO
}

func (s *Server) shareName() string {
	if s.ShareName != "" {
		return s.ShareName
	}
	return defaultShareName
}

func (s *Server) serverName() string {
	if s.ServerName != "" {
		return s.ServerName
	}
	return defaultServerName
}

// frameCap bounds one transport frame, which must hold a write of the
// advertised size and the structures around it.
func (s *Server) frameCap() int {
	return min(int(s.maxWrite())+frameHeadroom, maxFrameBytes)
}

// Serve accepts connections until ctx is canceled or the listener fails.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if err := s.init(); err != nil {
		return err
	}
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
	return s.serveConn(ctx, c)
}
