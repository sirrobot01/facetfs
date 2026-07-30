// Command sftp serves a directory over SFTP. It shows the application-owned
// side of the split: the app runs the SSH server, authenticates public keys,
// and accepts session channels; the sftp.Server only speaks the protocol on
// each accepted channel.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirrobot01/facetfs"
	facetftp "github.com/sirrobot01/facetfs/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {
	address := flag.String("addr", "127.0.0.1:2022", "listen address")
	root := flag.String("root", ".", "directory to serve")
	hostKeyPath := flag.String("host-key", "", "SSH host private key file")
	authorizedKeysPath := flag.String("authorized-keys", "", "OpenSSH authorized keys file")
	flag.Parse()

	if *hostKeyPath == "" || *authorizedKeysPath == "" {
		log.Fatal("-host-key and -authorized-keys are required")
	}
	hostKeyData, err := os.ReadFile(*hostKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyData)
	if err != nil {
		log.Fatal(err)
	}
	authorizedKeys, err := parseAuthorizedKeys(*authorizedKeysPath)
	if err != nil {
		log.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := authorizedKeys[string(key.Marshal())]; !ok {
				return nil, errors.New("public key rejected")
			}
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostKey)

	server := &facetftp.Server{FileSystem: facetfs.Dir(*root)}

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	log.Printf("serving %s at %s", *root, listener.Addr())
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Fatal(err)
		}
		go func() {
			if err := serveConn(ctx, connection, config, server); err != nil && ctx.Err() == nil {
				log.Printf("connection closed: %v", err)
			}
		}()
	}
}

// serveConn runs the SSH handshake on connection and delegates each session
// channel's sftp subsystem to server.Serve.
func serveConn(ctx context.Context, connection net.Conn, config *ssh.ServerConfig, server *facetftp.Server) error {
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	sshConnection, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return err
	}
	defer sshConnection.Close()
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return err
	}
	go ssh.DiscardRequests(requests)

	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		accepted, channelRequests, err := channel.Accept()
		if err != nil {
			continue
		}
		go func() {
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
				if err := server.Serve(ctx, accepted); err != nil && ctx.Err() == nil {
					log.Printf("sftp session: %v", err)
				}
				return
			}
		}()
	}
	return nil
}

func parseAuthorizedKeys(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]struct{})
	for len(bytes.TrimSpace(data)) > 0 {
		key, _, _, remaining, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, err
		}
		keys[string(key.Marshal())] = struct{}{}
		data = remaining
	}
	if len(keys) == 0 {
		return nil, errors.New("authorized-keys contains no public keys")
	}
	return keys, nil
}
