package facetfs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/memfs"
)

func lockServer(t *testing.T) (*facetfs.Server, facetfs.Request, facetfs.ObjectRef) {
	t.Helper()
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(context.Context, facetfs.Request, facetfs.AccessCheck) error { return nil }),
		Exports: []facetfs.Export{{
			ID: "data", Name: "Data", Backend: memfs.New(), Protocols: []facetfs.Protocol{facetfs.ProtocolWebDAV},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := facetfs.Request{
		Protocol:  facetfs.ProtocolWebDAV,
		SessionID: "session",
		Principal: facetfs.Principal{Subject: "user"},
	}
	root, _, err := server.Root(t.Context(), request, "data")
	if err != nil {
		t.Fatal(err)
	}
	return server, request, root
}

func createFile(t *testing.T, server *facetfs.Server, request facetfs.Request, parent facetfs.ObjectRef, name string) facetfs.ObjectRef {
	t.Helper()
	object, handle, _, err := server.Create(t.Context(), request, parent, name, facetfs.CreateOptions{
		Open: facetfs.OpenOptions{Access: facetfs.OpenWrite},
	})
	if err != nil {
		t.Fatalf("Create(%s) = %v", name, err)
	}
	if err := handle.Close(t.Context()); err != nil {
		t.Fatalf("Close(%s) = %v", name, err)
	}
	return object
}

// A document lock must not outlive the object it protects: the entry would hold
// a slot against the table ceiling until expiry, and a later object reusing the
// key would inherit a lock nobody took out on it.
func TestDocumentLockReleasedOnRemove(t *testing.T) {
	server, request, root := lockServer(t)
	object := createFile(t, server, request, root, "file")

	lock, err := server.AcquireLock(t.Context(), request, object, facetfs.DocumentLockRequest{Exclusive: true})
	if err != nil {
		t.Fatalf("AcquireLock = %v", err)
	}
	if err := server.Remove(t.Context(), request, root, "file", facetfs.RemoveFile); !errors.Is(err, facetfs.ErrLockConflict) {
		t.Fatalf("Remove without the token = %v, want ErrLockConflict", err)
	}

	holder := request
	holder.LockTokens = []string{lock.Token}
	if err := server.Remove(t.Context(), holder, root, "file", facetfs.RemoveFile); err != nil {
		t.Fatalf("Remove with the token = %v", err)
	}
	if _, ok := server.LockOf(object); ok {
		t.Fatal("the lock outlived the object it protected")
	}
}

// A rename that overwrites its destination destroys that object, so its lock
// goes with it. The renamed object keeps its identity and its lock.
func TestDocumentLockReleasedWhenRenameOverwrites(t *testing.T) {
	server, request, root := lockServer(t)
	source := createFile(t, server, request, root, "source")
	target := createFile(t, server, request, root, "target")

	sourceLock, err := server.AcquireLock(t.Context(), request, source, facetfs.DocumentLockRequest{Exclusive: true})
	if err != nil {
		t.Fatalf("AcquireLock(source) = %v", err)
	}
	targetLock, err := server.AcquireLock(t.Context(), request, target, facetfs.DocumentLockRequest{Exclusive: true})
	if err != nil {
		t.Fatalf("AcquireLock(target) = %v", err)
	}

	holder := request
	holder.LockTokens = []string{sourceLock.Token, targetLock.Token}
	if err := server.Rename(t.Context(), holder, root, "source", root, "target", facetfs.RenameOptions{Replace: true}); err != nil {
		t.Fatalf("Rename = %v", err)
	}
	if _, ok := server.LockOf(target); ok {
		t.Fatal("the overwritten object's lock survived the rename")
	}
	if _, ok := server.LockOf(source); !ok {
		t.Fatal("the renamed object lost the lock held on it")
	}
}
