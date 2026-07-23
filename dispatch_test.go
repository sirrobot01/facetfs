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
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV, Principal: facetfs.Principal{Subject: "user"}}
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
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV}
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
	request := facetfs.Request{Protocol: facetfs.ProtocolWebDAV}
	root, _, err := server.Root(t.Context(), request, "data")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := server.Create(t.Context(), request, root, "file", facetfs.CreateOptions{}); !errors.Is(err, facetfs.ErrReadOnly) {
		t.Fatalf("Create() = %v", err)
	}
}
