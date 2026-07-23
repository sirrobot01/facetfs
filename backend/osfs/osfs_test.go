package osfs_test

import (
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/osfs"
	"github.com/sirrobot01/facetfs/backendtest"
)

func TestBackendContract(t *testing.T) {
	backendtest.BackendContract(t, func(t *testing.T) facetfs.Backend {
		backend, err := osfs.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return backend
	})
}

func TestObjectSurvivesParentRename(t *testing.T) {
	backend, err := osfs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := backend.Root(t.Context(), facetfs.Request{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	dir, _, err := backend.Mkdir(t.Context(), facetfs.Request{}, root, "old", facetfs.SetAttr{})
	if err != nil {
		t.Fatal(err)
	}
	object, handle, _, err := backend.Create(t.Context(), facetfs.Request{}, dir, "file", facetfs.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := backend.Rename(t.Context(), facetfs.Request{}, root, "old", root, "new", facetfs.RenameOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.GetAttr(t.Context(), facetfs.Request{}, object, facetfs.AttrAll); err != nil {
		t.Fatalf("GetAttr() after parent rename = %v", err)
	}
}
