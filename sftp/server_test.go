package sftp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	clientsftp "github.com/pkg/sftp"
	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/memfs"
	serversftp "github.com/sirrobot01/facetfs/sftp"
	"github.com/sirrobot01/facetfs/webdav"
	"golang.org/x/crypto/ssh"
)

func TestSFTPWorkflow(t *testing.T) {
	_, client, sshClient := startServer(t)

	session, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err == nil {
		t.Fatal("shell request succeeded")
	}
	_ = session.Close()
	if connection, err := sshClient.Dial("tcp", "example.com:80"); err == nil {
		_ = connection.Close()
		t.Fatal("TCP forwarding succeeded")
	}

	if err := client.Mkdir("/dir"); err != nil {
		t.Fatal(err)
	}
	file, err := client.Create("/dir/file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("world"), 6); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("hello "), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	file, err = client.Open("/dir/file")
	if err != nil {
		t.Fatal(err)
	}
	var chunks [2][]byte
	var readErrors [2]error
	var reads sync.WaitGroup
	reads.Go(func() {
		chunks[0] = make([]byte, 5)
		_, readErrors[0] = file.ReadAt(chunks[0], 0)
	})
	reads.Go(func() {
		chunks[1] = make([]byte, 5)
		_, readErrors[1] = file.ReadAt(chunks[1], 6)
	})
	reads.Wait()
	if readErrors[0] != nil || readErrors[1] != nil || string(chunks[0]) != "hello" || string(chunks[1]) != "world" {
		t.Fatalf("parallel reads = %q/%v, %q/%v", chunks[0], readErrors[0], chunks[1], readErrors[1])
	}
	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if string(contents) != "hello world" {
		t.Fatalf("file contents = %q", contents)
	}
	if err := client.Truncate("/dir/file", 5); err != nil {
		t.Fatal(err)
	}
	if err := client.Symlink("file", "/dir/link"); err != nil {
		t.Fatal(err)
	}
	if target, err := client.ReadLink("/dir/link"); err != nil || target != "file" {
		t.Fatalf("ReadLink = %q, %v", target, err)
	}
	if info, err := client.Lstat("/dir/link"); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat = %v, %v", info, err)
	}
	if info, err := client.Stat("/dir/link"); err != nil || info.Size() != 5 {
		t.Fatalf("Stat = %v, %v", info, err)
	}
	entries, err := client.ReadDir("/dir")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"file", "link"}) {
		t.Fatalf("ReadDir names = %v", names)
	}
	if _, err := client.StatVFS("/"); err != nil {
		t.Fatal(err)
	}
	if err := client.PosixRename("/dir/file", "/dir/renamed"); err != nil {
		t.Fatal(err)
	}
	if err := client.Remove("/dir/link"); err != nil {
		t.Fatal(err)
	}
	if err := client.Remove("/dir/renamed"); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveDirectory("/dir"); err != nil {
		t.Fatal(err)
	}
}

func TestWebDAVAndSFTPShareState(t *testing.T) {
	server, client, _ := startServer(t)
	handler, err := webdav.New(server, webdav.Options{
		ExportID: "data",
		Authenticate: func(context.Context, *http.Request) (facetfs.Principal, error) {
			return facetfs.Principal{Subject: "user"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/shared", bytes.NewBufferString("shared data"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("WebDAV PUT = %d: %s", response.Code, response.Body.String())
	}
	file, err := client.Open("/shared")
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil || string(contents) != "shared data" {
		t.Fatalf("SFTP read = %q, %v", contents, err)
	}
	if err := client.PosixRename("/shared", "/moved"); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/moved", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "shared data" {
		t.Fatalf("WebDAV GET = %d, %q", response.Code, response.Body.String())
	}
}

func TestPublicKeyAuthentication(t *testing.T) {
	_, _, clientKey := keyPair(t)
	hostSigner, hostPublicKey, _ := keyPair(t)
	core, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(context.Context, facetfs.Request, facetfs.AccessCheck) error { return nil }),
		Exports:    []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := serversftp.New(core, serversftp.Options{
		ExportID: "data", HostKeys: []ssh.Signer{hostSigner},
		AuthenticatePublicKey: func(context.Context, string, ssh.PublicKey, net.Addr) (facetfs.Principal, error) {
			return facetfs.Principal{}, errors.New("denied")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	_, err = ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User: "user", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), hostPublicKey.Marshal()) {
				return errors.New("unexpected host key")
			}
			return nil
		},
		Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("authentication succeeded")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func startServer(t *testing.T) (*facetfs.Server, *clientsftp.Client, *ssh.Client) {
	t.Helper()
	hostSigner, hostPublicKey, clientSigner := keyPair(t)
	core, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(_ context.Context, request facetfs.Request, _ facetfs.AccessCheck) error {
			if request.Principal.Subject != "user" {
				return facetfs.ErrAccessDenied
			}
			return nil
		}),
		Exports: []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := serversftp.New(core, serversftp.Options{
		ExportID: "data", HostKeys: []ssh.Signer{hostSigner},
		AuthenticatePublicKey: func(_ context.Context, user string, key ssh.PublicKey, _ net.Addr) (facetfs.Principal, error) {
			if user != "user" || !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return facetfs.Principal{}, errors.New("denied")
			}
			return facetfs.Principal{Subject: "user", Name: user, Method: "publickey"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	sshClient, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User: "user", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), hostPublicKey.Marshal()) {
				return errors.New("unexpected host key")
			}
			return nil
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	client, err := clientsftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = sshClient.Close()
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return core, client, sshClient
}

func keyPair(t *testing.T) (ssh.Signer, ssh.PublicKey, ssh.Signer) {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return hostSigner, hostSigner.PublicKey(), clientSigner
}
