package facetfs_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/memfs"
)

func TestServerDispatch(t *testing.T) {
	var mu sync.Mutex
	var actions []facetfs.Action
	authorizer := facetfs.AuthorizerFunc(func(_ context.Context, _ facetfs.Request, check facetfs.AccessCheck) error {
		mu.Lock()
		actions = append(actions, check.Action)
		mu.Unlock()
		return nil
	})
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: authorizer,
		Exports: []facetfs.Export{{
			ID: "data", Name: "Data", Backend: memfs.New(), Protocols: []facetfs.Protocol{facetfs.ProtocolWebDAV},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "session", Principal: facetfs.Principal{Subject: "user"}}
	root, _, err := server.Root(t.Context(), request, "data")
	if err != nil {
		t.Fatal(err)
	}
	_, handle, _, err := server.Create(t.Context(), request, root, "file", facetfs.CreateOptions{
		Open: facetfs.OpenOptions{Access: facetfs.OpenRead | facetfs.OpenWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	mutable, ok := handle.(facetfs.MutableHandle)
	if !ok {
		t.Fatal("Create() returned a read-only handle")
	}
	if _, err := mutable.WriteAt(t.Context(), []byte("data"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := mutable.ReadAt(t.Context(), make([]byte, 4), 0); err != nil {
		t.Fatal(err)
	}
	if err := mutable.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	got := append([]facetfs.Action(nil), actions...)
	mu.Unlock()
	want := []facetfs.Action{facetfs.ActionRoot, facetfs.ActionCreate, facetfs.ActionWrite, facetfs.ActionRead}
	if len(got) != len(want) {
		t.Fatalf("actions = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("actions = %v", got)
		}
	}
}

func TestHandleReauthorizesOperations(t *testing.T) {
	var denyWrite atomic.Bool
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(_ context.Context, _ facetfs.Request, check facetfs.AccessCheck) error {
			if check.Action == facetfs.ActionWrite && denyWrite.Load() {
				return facetfs.ErrAccessDenied
			}
			return nil
		}),
		Exports: []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "session"}
	root, _, err := server.Root(t.Context(), request, "data")
	if err != nil {
		t.Fatal(err)
	}
	_, handle, _, err := server.Create(t.Context(), request, root, "file", facetfs.CreateOptions{
		Open: facetfs.OpenOptions{Access: facetfs.OpenWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	denyWrite.Store(true)
	if _, err := handle.(facetfs.MutableHandle).WriteAt(t.Context(), []byte("x"), 0); !errors.Is(err, facetfs.ErrAccessDenied) {
		t.Fatalf("WriteAt() = %v", err)
	}
	if err := handle.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestExportVisibilityAndDefaultAuthorization(t *testing.T) {
	server, err := facetfs.New(t.Context(), facetfs.Config{Exports: []facetfs.Export{{
		ID: "data", Name: "Data", Backend: memfs.New(), Protocols: []facetfs.Protocol{facetfs.ProtocolWebDAV},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.Root(t.Context(), facetfs.Request{Protocol: facetfs.ProtocolSFTP}, "data"); !errors.Is(err, facetfs.ErrNotFound) {
		t.Fatalf("hidden export = %v", err)
	}
	if _, _, err := server.Root(t.Context(), facetfs.Request{Protocol: facetfs.ProtocolWebDAV}, "data"); !errors.Is(err, facetfs.ErrAuthenticationRequired) {
		t.Fatalf("anonymous request = %v", err)
	}
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, Principal: facetfs.Principal{Subject: "user"}}
	if _, _, err := server.Root(t.Context(), request, "data"); !errors.Is(err, facetfs.ErrAccessDenied) {
		t.Fatalf("default authorization = %v", err)
	}
}

func TestReadOnlyExport(t *testing.T) {
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(context.Context, facetfs.Request, facetfs.AccessCheck) error { return nil }),
		Exports:    []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New(), ReadOnly: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "session"}
	root, _, err := server.Root(t.Context(), request, "data")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := server.Create(t.Context(), request, root, "file", facetfs.CreateOptions{}); !errors.Is(err, facetfs.ErrReadOnly) {
		t.Fatalf("Create() = %v", err)
	}
}

func TestShareReservations(t *testing.T) {
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(context.Context, facetfs.Request, facetfs.AccessCheck) error { return nil }),
		Exports:    []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "one"}
	root, _, err := server.Root(t.Context(), request, "data")
	if err != nil {
		t.Fatal(err)
	}
	object, first, _, err := server.Create(t.Context(), request, root, "file", facetfs.CreateOptions{
		Open: facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: facetfs.ShareRead},
	})
	if err != nil {
		t.Fatal(err)
	}
	all := facetfs.ShareRead | facetfs.ShareWrite | facetfs.ShareDelete
	if _, err := server.Open(t.Context(), facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "two"}, object, facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: all}); !errors.Is(err, facetfs.ErrLockConflict) {
		t.Fatalf("conflicting Open() = %v", err)
	}
	if err := server.Remove(t.Context(), request, root, "file", facetfs.RemoveFile); !errors.Is(err, facetfs.ErrLockConflict) {
		t.Fatalf("conflicting Remove() = %v", err)
	}
	if err := first.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	second, err := server.Open(t.Context(), facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "two"}, object, facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: all})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRangeLocksAndSessionCleanup(t *testing.T) {
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(context.Context, facetfs.Request, facetfs.AccessCheck) error { return nil }),
		Exports:    []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	all := facetfs.ShareRead | facetfs.ShareWrite | facetfs.ShareDelete
	firstRequest := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "one"}
	secondRequest := facetfs.Request{Protocol: facetfs.ProtocolSFTP, SessionID: "two"}
	root, _, err := server.Root(t.Context(), firstRequest, "data")
	if err != nil {
		t.Fatal(err)
	}
	object, first, _, err := server.Create(t.Context(), firstRequest, root, "file", facetfs.CreateOptions{
		Open: facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: all},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.Open(t.Context(), secondRequest, object, facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: all})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := server.Lock(t.Context(), firstRequest, object, facetfs.LockOptions{Offset: 0, Length: 10, Exclusive: true})
	if err != nil {
		t.Fatal(err)
	}
	writer := second.(facetfs.MutableHandle)
	if _, err := writer.WriteAt(t.Context(), []byte("x"), 5); !errors.Is(err, facetfs.ErrLockConflict) {
		t.Fatalf("overlapping WriteAt() = %v", err)
	}
	if _, err := writer.WriteAt(t.Context(), []byte("x"), 10); err != nil {
		t.Fatalf("non-overlapping WriteAt() = %v", err)
	}
	if err := server.Unlock(secondRequest, lock); !errors.Is(err, facetfs.ErrAccessDenied) {
		t.Fatalf("foreign Unlock() = %v", err)
	}
	if err := server.Unlock(firstRequest, facetfs.Lock{}); !errors.Is(err, facetfs.ErrInvalid) {
		t.Fatalf("zero Unlock() = %v", err)
	}
	if err := server.Unlock(firstRequest, lock); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseSession(t.Context(), "two"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteAt(t.Context(), []byte("x"), 0); !errors.Is(err, facetfs.ErrInvalid) {
		t.Fatalf("WriteAt() after session cleanup = %v", err)
	}
	if err := first.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestChangeEvents(t *testing.T) {
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(context.Context, facetfs.Request, facetfs.AccessCheck) error { return nil }),
		Exports:    []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := server.SubscribeChanges(8)
	defer cancel()
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, SessionID: "session"}
	root, _, err := server.Root(t.Context(), request, "data")
	if err != nil {
		t.Fatal(err)
	}
	object, handle, _, err := server.Create(t.Context(), request, root, "file", facetfs.CreateOptions{
		Open: facetfs.OpenOptions{Access: facetfs.OpenWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	mutable := handle.(facetfs.MutableHandle)
	if _, err := mutable.WriteAt(t.Context(), []byte("data"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := mutable.SetAttr(t.Context(), facetfs.SetAttr{}); err != nil {
		t.Fatal(err)
	}
	if err := mutable.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := server.Rename(t.Context(), request, root, "file", root, "renamed", facetfs.RenameOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := server.Remove(t.Context(), request, root, "renamed", facetfs.RemoveFile); err != nil {
		t.Fatal(err)
	}
	want := []facetfs.ChangeKind{
		facetfs.ChangeCreated, facetfs.ChangeData, facetfs.ChangeMetadata, facetfs.ChangeNamespace, facetfs.ChangeRemoved,
	}
	for _, kind := range want {
		if event := <-events; event.Kind != kind || event.Object != object {
			t.Fatalf("event = %#v, want kind %v and object %v", event, kind, object)
		}
	}
}
