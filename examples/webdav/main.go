package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/osfs"
	"github.com/sirrobot01/facetfs/webdav"
)

func main() {
	address := flag.String("addr", "127.0.0.1:8080", "listen address")
	root := flag.String("root", ".", "directory to export")
	certificate := flag.String("tls-cert", "", "TLS certificate file")
	privateKey := flag.String("tls-key", "", "TLS private key file")
	flag.Parse()

	username := os.Getenv("FACETFS_USER")
	password := os.Getenv("FACETFS_PASSWORD")
	if username == "" || password == "" {
		log.Fatal("FACETFS_USER and FACETFS_PASSWORD are required")
	}
	if (*certificate == "") != (*privateKey == "") {
		log.Fatal("-tls-cert and -tls-key must be provided together")
	}
	usernameHash := sha256.Sum256([]byte(username))
	passwordHash := sha256.Sum256([]byte(password))

	backend, err := osfs.New(*root)
	if err != nil {
		log.Fatal(err)
	}
	runtime, err := facetfs.New(context.Background(), facetfs.Config{
		Exports: []facetfs.Export{{
			ID:        "data",
			Name:      "Data",
			Backend:   backend,
			Protocols: []facetfs.Protocol{facetfs.ProtocolWebDAV},
		}},
		Authorizer: facetfs.AuthorizerFunc(func(_ context.Context, request facetfs.Request, _ facetfs.AccessCheck) error {
			if request.Principal.Subject != username {
				return facetfs.ErrAccessDenied
			}
			return nil
		}),
	})
	if err != nil {
		log.Fatal(err)
	}
	handler, err := webdav.New(runtime, webdav.Options{
		ExportID:           "data",
		Prefix:             "/dav",
		AllowInsecureBasic: *certificate == "",
		Authenticate: func(_ context.Context, request *http.Request) (facetfs.Principal, error) {
			providedUser, providedPassword, ok := request.BasicAuth()
			providedUserHash := sha256.Sum256([]byte(providedUser))
			providedPasswordHash := sha256.Sum256([]byte(providedPassword))
			userMatch := subtle.ConstantTimeCompare(providedUserHash[:], usernameHash[:])
			passwordMatch := subtle.ConstantTimeCompare(providedPasswordHash[:], passwordHash[:])
			if !ok || userMatch&passwordMatch != 1 {
				return facetfs.Principal{}, facetfs.ErrAuthenticationRequired
			}
			return facetfs.Principal{Subject: username, Name: username, Method: "basic"}, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	if *certificate == "" {
		tcpAddress, ok := listener.Addr().(*net.TCPAddr)
		if !ok || !tcpAddress.IP.IsLoopback() {
			_ = listener.Close()
			log.Fatal("plaintext development mode requires a loopback listen address")
		}
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("serving %s at %s/dav", *root, listener.Addr())
	if *certificate == "" {
		err = server.Serve(listener)
	} else {
		err = server.ServeTLS(listener, *certificate, *privateKey)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
