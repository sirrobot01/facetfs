// Command smb serves a directory as one SMB2/SMB3 share. It is deliberately
// small: the application binds the listener and owns the credential lookup;
// smb.Server owns NTLMv2 and the signed protocol session.
//
// The package does not implement SMB encryption. Use this example only on a
// trusted network. The default listener is loopback and unprivileged.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/smb"
)

type oneUser struct {
	domain string
	user   string
	hash   []byte
}

func (a oneUser) NTHash(_ context.Context, domain, user string) ([]byte, error) {
	if !strings.EqualFold(domain, a.domain) || !strings.EqualFold(user, a.user) {
		return nil, errors.New("unknown user")
	}
	return append([]byte(nil), a.hash...), nil
}

func main() {
	address := flag.String("addr", "127.0.0.1:1445", "listen address (SMB clients normally use port 445)")
	root := flag.String("root", ".", "directory to serve")
	share := flag.String("share", "share", "SMB share name")
	domain := flag.String("domain", "WORKGROUP", "accepted NTLM domain")
	requireSigning := flag.Bool("require-signing", true, "refuse clients that do not enable signing")
	flag.Parse()

	user, password := os.Getenv("FACETFS_USER"), os.Getenv("FACETFS_PASSWORD")
	if user == "" || password == "" {
		log.Fatal("FACETFS_USER and FACETFS_PASSWORD are required")
	}
	served, err := facetfs.OpenDir(*root)
	if err != nil {
		log.Fatal(err)
	}
	defer served.Close()

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := &smb.Server{
		FileSystem:     served,
		Authenticator:  oneUser{domain: *domain, user: user, hash: smb.NTHash(password)},
		ShareName:      *share,
		RequireSigning: *requireSigning,
		Logger:         func(err error) { log.Printf("connection: %v", err) },
	}
	log.Printf("serving %s as \\\\%s\\%s at %s", *root, serverName(listener), *share, listener.Addr())
	if err := server.Serve(ctx, listener); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func serverName(listener net.Listener) string {
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil || host == "" {
		return "localhost"
	}
	return host
}
