package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/osfs"
	facetftp "github.com/sirrobot01/facetfs/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {
	address := flag.String("addr", "127.0.0.1:2022", "listen address")
	root := flag.String("root", ".", "directory to export")
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
	authorizedKeysData, err := os.ReadFile(*authorizedKeysPath)
	if err != nil {
		log.Fatal(err)
	}
	authorizedKeys := make(map[string]struct{})
	for len(bytes.TrimSpace(authorizedKeysData)) > 0 {
		key, _, _, remaining, err := ssh.ParseAuthorizedKey(authorizedKeysData)
		if err != nil {
			log.Fatal(err)
		}
		authorizedKeys[string(key.Marshal())] = struct{}{}
		authorizedKeysData = remaining
	}
	if len(authorizedKeys) == 0 {
		log.Fatal("authorized-keys contains no public keys")
	}

	backend, err := osfs.New(*root)
	if err != nil {
		log.Fatal(err)
	}
	runtime, err := facetfs.New(context.Background(), facetfs.Config{
		Exports: []facetfs.Export{{
			ID:        "data",
			Name:      "Data",
			Backend:   backend,
			Protocols: []facetfs.Protocol{facetfs.ProtocolSFTP},
		}},
		Authorizer: facetfs.AuthorizerFunc(func(_ context.Context, request facetfs.Request, _ facetfs.AccessCheck) error {
			if request.Principal.Subject == "" {
				return facetfs.ErrAccessDenied
			}
			return nil
		}),
	})
	if err != nil {
		log.Fatal(err)
	}
	server, err := facetftp.New(runtime, facetftp.Options{
		ExportID: "data",
		HostKeys: []ssh.Signer{hostKey},
		AuthenticatePublicKey: func(_ context.Context, username string, key ssh.PublicKey, _ net.Addr) (facetfs.Principal, error) {
			if _, ok := authorizedKeys[string(key.Marshal())]; !ok {
				return facetfs.Principal{}, facetfs.ErrAuthenticationRequired
			}
			return facetfs.Principal{Subject: username, Name: username, Method: "publickey"}, nil
		},
		OnConnectionError: func(err error) {
			log.Printf("connection closed: %v", err)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("serving %s at %s", *root, listener.Addr())
	if err := server.Serve(ctx, listener); err != nil {
		log.Fatal(err)
	}
}
