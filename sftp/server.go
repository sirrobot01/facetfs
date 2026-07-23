// Package sftp provides an SSH File Transfer Protocol frontend for FacetFS.
package sftp

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/sirrobot01/facetfs"
	"golang.org/x/crypto/ssh"
)

// PublicKeyAuthenticator verifies an SSH public key and returns its canonical identity.
type PublicKeyAuthenticator func(context.Context, string, ssh.PublicKey, net.Addr) (facetfs.Principal, error)

// Options configures an SFTP server for one export.
type Options struct {
	ExportID              string
	HostKeys              []ssh.Signer
	AuthenticatePublicKey PublicKeyAuthenticator
	MaxConnections        int
	MaxSessions           int
	MaxPacketBytes        uint32
	MaxDirectoryEntries   int
	HandshakeTimeout      time.Duration
	OnConnectionError     func(error)
}

// Server serves one FacetFS export over SSH and SFTP.
type Server struct {
	server              *facetfs.Server
	exportID            string
	hostKeys            []ssh.Signer
	authenticate        PublicKeyAuthenticator
	maxConnections      int
	maxSessions         int
	maxPacketBytes      uint32
	maxDirectoryEntries int
	handshakeTimeout    time.Duration
	atomicRename        bool
	onConnectionError   func(error)
}

// New validates options and constructs an SFTP server.
func New(server *facetfs.Server, options Options) (*Server, error) {
	if server == nil || options.ExportID == "" || len(options.HostKeys) == 0 || options.AuthenticatePublicKey == nil {
		return nil, facetfs.ErrInvalid
	}
	for _, key := range options.HostKeys {
		if key == nil {
			return nil, facetfs.ErrInvalid
		}
	}
	export, ok := server.Export(options.ExportID)
	if !ok || !export.Supports(facetfs.ProtocolSFTP) {
		return nil, facetfs.ErrNotFound
	}
	if options.MaxConnections <= 0 {
		options.MaxConnections = 128
	}
	if options.MaxSessions <= 0 {
		options.MaxSessions = 4
	}
	if options.MaxPacketBytes == 0 {
		options.MaxPacketBytes = 1 << 20
	}
	if options.MaxPacketBytes < 32<<10 || options.MaxPacketBytes > 16<<20 {
		return nil, facetfs.ErrInvalid
	}
	if options.MaxDirectoryEntries <= 0 {
		options.MaxDirectoryEntries = 100_000
	}
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = 15 * time.Second
	}
	return &Server{
		server:              server,
		exportID:            options.ExportID,
		hostKeys:            append([]ssh.Signer(nil), options.HostKeys...),
		authenticate:        options.AuthenticatePublicKey,
		maxConnections:      options.MaxConnections,
		maxSessions:         options.MaxSessions,
		maxPacketBytes:      options.MaxPacketBytes,
		maxDirectoryEntries: options.MaxDirectoryEntries,
		handshakeTimeout:    options.HandshakeTimeout,
		atomicRename:        export.Capabilities.AtomicRename,
		onConnectionError:   options.OnConnectionError,
	}, nil
}

// Serve accepts SSH connections until ctx is canceled or the listener fails.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil {
		return facetfs.ErrInvalid
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		select {
		case <-serveCtx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)

	connections := make(chan struct{}, s.maxConnections)
	var active sync.WaitGroup
	for {
		connection, err := listener.Accept()
		if err != nil {
			cancel()
			active.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connections <- struct{}{}:
			active.Go(func() {
				defer func() { <-connections }()
				if err := s.ServeConn(serveCtx, connection); err != nil && serveCtx.Err() == nil && s.onConnectionError != nil {
					s.onConnectionError(err)
				}
			})
		default:
			_ = connection.Close()
		}
	}
}

// ServeConn serves a single SSH connection.
func (s *Server) ServeConn(ctx context.Context, connection net.Conn) error {
	if ctx == nil || connection == nil {
		return facetfs.ErrInvalid
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return err
	}

	type approvedKey struct {
		user string
		key  string
	}
	approved := make(map[approvedKey]facetfs.Principal)
	var approvedMu sync.Mutex
	var principal facetfs.Principal
	algorithms := ssh.SupportedAlgorithms()
	config := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
		PublicKeyAuthAlgorithms: algorithms.PublicKeyAuths,
		MaxAuthTries:            6,
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			identity, err := s.authenticate(ctx, metadata.User(), key, metadata.RemoteAddr())
			if err != nil || identity.Subject == "" {
				return nil, errors.New("sftp: public key rejected")
			}
			approvedMu.Lock()
			approved[approvedKey{user: metadata.User(), key: string(key.Marshal())}] = identity
			approvedMu.Unlock()
			return &ssh.Permissions{}, nil
		},
		VerifiedPublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey, permissions *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			approvedMu.Lock()
			identity, ok := approved[approvedKey{user: metadata.User(), key: string(key.Marshal())}]
			approvedMu.Unlock()
			if !ok {
				return nil, errors.New("sftp: public key rejected")
			}
			principal = identity
			return permissions, nil
		},
	}
	for _, key := range s.hostKeys {
		config.AddHostKey(key)
	}

	sshConnection, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return err
	}
	defer sshConnection.Close()
	sessionID := rand.Text()
	request := facetfs.Request{
		Principal:  principal,
		Protocol:   facetfs.ProtocolSFTP,
		ClientID:   sshConnection.RemoteAddr().String(),
		SessionID:  sessionID,
		RemoteAddr: sshConnection.RemoteAddr(),
	}
	defer s.server.CloseSession(context.WithoutCancel(ctx), sessionID)

	go func() {
		for request := range requests {
			_ = request.Reply(false, nil)
		}
	}()
	handler := &handler{
		ctx:                 ctx,
		server:              s.server,
		exportID:            s.exportID,
		request:             request,
		atomicRename:        s.atomicRename,
		maxDirectoryEntries: s.maxDirectoryEntries,
	}
	var sessions sync.WaitGroup
	var sessionErr error
	var sessionErrMu sync.Mutex
	sessionSlots := make(chan struct{}, s.maxSessions)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		select {
		case sessionSlots <- struct{}{}:
		default:
			_ = channel.Reject(ssh.ResourceShortage, "too many sessions")
			continue
		}
		accepted, channelRequests, err := channel.Accept()
		if err != nil {
			<-sessionSlots
			continue
		}
		sessions.Go(func() {
			defer func() { <-sessionSlots }()
			defer accepted.Close()
			for channelRequest := range channelRequests {
				var subsystem struct{ Name string }
				if channelRequest.Type != "subsystem" || ssh.Unmarshal(channelRequest.Payload, &subsystem) != nil || subsystem.Name != "sftp" {
					_ = channelRequest.Reply(false, nil)
					continue
				}
				if err := channelRequest.Reply(true, nil); err != nil {
					return
				}
				server := pkgsftp.NewRequestServer(accepted, pkgsftp.Handlers{
					FileGet:  handler,
					FilePut:  handler,
					FileCmd:  handler,
					FileList: handler,
				}, pkgsftp.WithRSMaxTxPacket(s.maxPacketBytes))
				if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					sessionErrMu.Lock()
					sessionErr = errors.Join(sessionErr, err)
					sessionErrMu.Unlock()
				}
				return
			}
		})
	}
	sessions.Wait()
	return sessionErr
}
