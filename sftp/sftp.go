// Package sftp provides an SFTP server that serves a facetfs.FileSystem on
// already-authenticated streams. The caller owns the SSH transport and
// authentication: run an SSH server, accept the "sftp" subsystem request on a
// session channel, and pass the channel to Serve.
package sftp

import (
	"context"
	"errors"
	"io"

	pkgsftp "github.com/pkg/sftp"
	"github.com/sirrobot01/facetfs"
)

const defaultDirectoryEntries = 100_000

// Server serves SFTP sessions from a FileSystem. The zero value of every
// optional field is usable.
type Server struct {
	// FileSystem is the served filesystem. Required.
	//
	// Optional interfaces unlock protocol features: facetfs.SymlinkFS serves
	// symlink, readlink, and lstat; facetfs.SetStatFS serves setstat;
	// facetfs.StatVFSFS serves statvfs. Requests needing an interface the
	// FileSystem lacks fail with SSH_FX_OP_UNSUPPORTED.
	FileSystem facetfs.FileSystem
	// MaxPacketBytes caps the transmitted SFTP packet size. Zero means the
	// github.com/pkg/sftp default.
	MaxPacketBytes uint32
	// MaxDirectoryEntries caps a single directory listing. Zero means 100 000.
	MaxDirectoryEntries int
}

// Serve speaks SFTP on rwc — typically an ssh.Channel that accepted the
// "sftp" subsystem — until the client disconnects or ctx is canceled.
// Cancellation closes rwc. Serve returns nil on a clean client disconnect.
func (s *Server) Serve(ctx context.Context, rwc io.ReadWriteCloser) error {
	if s.FileSystem == nil {
		return errors.New("sftp: FileSystem is required")
	}
	maxEntries := s.MaxDirectoryEntries
	if maxEntries <= 0 {
		maxEntries = defaultDirectoryEntries
	}
	h := &handler{ctx: ctx, fs: s.FileSystem, maxDirectoryEntries: maxEntries}
	var options []pkgsftp.RequestServerOption
	if s.MaxPacketBytes > 0 {
		options = append(options, pkgsftp.WithRSMaxTxPacket(s.MaxPacketBytes))
	}
	server := pkgsftp.NewRequestServer(rwc, pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}, options...)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = rwc.Close()
		case <-done:
		}
	}()

	err := server.Serve()
	_ = server.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	return err
}
