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
	"slices"
	"sync"
	"testing"
	"time"

	clientsftp "github.com/pkg/sftp"
	"github.com/sirrobot01/facetfs"
	serversftp "github.com/sirrobot01/facetfs/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSFTPWorkflow(t *testing.T) {
	client := startServer(t, facetfs.NewMemFS())

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
	// SSH_FXP_RENAME must refuse to replace an existing target.
	if err := client.Rename("/dir/renamed", "/dir/link"); err == nil {
		t.Fatal("Rename onto an existing target succeeded")
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

// A FileSystem without the optional interfaces serves core operations and
// refuses the gated ones.
func TestOptionalInterfaceGating(t *testing.T) {
	client := startServer(t, coreOnly{facetfs.NewMemFS()})

	file, err := client.Create("/file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Symlink("file", "/link"); err == nil {
		t.Fatal("Symlink succeeded without SymlinkFS")
	}
	if _, err := client.StatVFS("/"); err == nil {
		t.Fatal("StatVFS succeeded without StatVFSFS")
	}
	if err := client.Chmod("/file", 0o600); err == nil {
		t.Fatal("Chmod succeeded without SetStatFS")
	}
	// Lstat falls back to Stat rather than failing.
	if info, err := client.Lstat("/file"); err != nil || info.Size() != 4 {
		t.Fatalf("Lstat fallback = %v, %v", info, err)
	}
}

// coreOnly hides every optional interface of the wrapped FileSystem.
type coreOnly struct{ facetfs.FileSystem }

// startServer runs a minimal SSH server that delegates the sftp subsystem to
// sftp.Server.Serve, and returns a connected pkg/sftp client. The SSH plumbing
// is what an application embedding this package writes itself.
func startServer(t *testing.T, fsys facetfs.FileSystem) *clientsftp.Client {
	t.Helper()
	hostSigner, clientSigner := keyPair(t)

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() != "user" || !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return nil, errors.New("public key rejected")
			}
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var serving sync.WaitGroup
	serving.Go(func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		sshConnection, channels, requests, err := ssh.NewServerConn(connection, config)
		if err != nil {
			return
		}
		defer sshConnection.Close()
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
			serving.Go(func() {
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
					server := &serversftp.Server{FileSystem: fsys}
					if err := server.Serve(ctx, accepted); err != nil && ctx.Err() == nil {
						t.Errorf("Serve: %v", err)
					}
					return
				}
			})
		}
	})

	sshClient, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User: "user", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), hostSigner.PublicKey().Marshal()) {
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
		_ = listener.Close()
		cancel()
		serving.Wait()
	})
	return client
}

func keyPair(t *testing.T) (host, client ssh.Signer) {
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
	return hostSigner, clientSigner
}
