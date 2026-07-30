// Command webdav serves a directory over WebDAV behind HTTP basic
// authentication. It shows the application-owned side of the split: the app
// runs the HTTP server, terminates TLS, and authenticates requests; the
// webdav.Handler only speaks the protocol.
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
	"github.com/sirrobot01/facetfs/webdav"
)

func main() {
	address := flag.String("addr", "127.0.0.1:8080", "listen address")
	root := flag.String("root", ".", "directory to serve")
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

	handler := &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: facetfs.Dir(*root),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
		},
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
		Handler:           basicAuth(username, password, handler),
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

// basicAuth wraps handler with constant-time HTTP basic authentication.
func basicAuth(username, password string, handler http.Handler) http.Handler {
	usernameHash := sha256.Sum256([]byte(username))
	passwordHash := sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providedUser, providedPassword, ok := r.BasicAuth()
		providedUserHash := sha256.Sum256([]byte(providedUser))
		providedPasswordHash := sha256.Sum256([]byte(providedPassword))
		userMatch := subtle.ConstantTimeCompare(providedUserHash[:], usernameHash[:])
		passwordMatch := subtle.ConstantTimeCompare(providedPasswordHash[:], passwordHash[:])
		if !ok || userMatch&passwordMatch != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="facetfs"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}
