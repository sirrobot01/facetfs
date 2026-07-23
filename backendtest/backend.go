package backendtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"testing"

	"github.com/sirrobot01/facetfs"
)

type BackendFactory func(*testing.T) facetfs.Backend

// BackendContract runs each test against a new backend from newBackend.
func BackendContract(t *testing.T, newBackend BackendFactory) {
	t.Helper()

	t.Run("capabilities", func(t *testing.T) {
		backend := newBackend(t)
		caps, err := backend.Capabilities(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !caps.StableObjectIDs {
			t.Fatal("backend does not provide stable object IDs")
		}
		if _, ok := backend.(facetfs.MutableBackend); !caps.ReadOnly && !ok {
			t.Fatal("writable backend does not implement facetfs.MutableBackend")
		}
	})

	t.Run("files", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		object, handle := createFile(t, backend, root, "file")

		if handle.ID() == "" || handle.Object() != object {
			t.Fatal("invalid handle identity")
		}
		if _, err := handle.WriteAt(t.Context(), []byte("world"), 5); err != nil {
			t.Fatal(err)
		}
		if _, err := handle.WriteAt(t.Context(), []byte("hello"), 0); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 10)
		if n, err := handle.ReadAt(t.Context(), buf, 0); err != nil || n != len(buf) {
			t.Fatalf("ReadAt() = %d, %v", n, err)
		}
		if string(buf) != "helloworld" {
			t.Fatalf("ReadAt() = %q", buf)
		}
		buf = make([]byte, 11)
		if n, err := handle.ReadAt(t.Context(), buf, 0); n != 10 || !errors.Is(err, io.EOF) {
			t.Fatalf("short ReadAt() = %d, %v", n, err)
		}
		if err := handle.Flush(t.Context(), true); err != nil {
			t.Fatal(err)
		}

		found, got, err := backend.Lookup(t.Context(), facetfs.Request{}, root, "file")
		if err != nil {
			t.Fatal(err)
		}
		if found != object || got.Size != 10 || got.FileID != object.NodeID {
			t.Fatalf("Lookup() = %#v, %#v", found, got)
		}

		size := int64(5)
		mode := fs.FileMode(0o640)
		got, err = handle.SetAttr(t.Context(), facetfs.SetAttr{Size: &size, Mode: &mode})
		if err != nil {
			t.Fatal(err)
		}
		if got.Size != size || got.Mode.Perm() != mode {
			t.Fatalf("SetAttr() = %#v", got)
		}
		if err := handle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := handle.Close(t.Context()); err != nil {
			t.Fatalf("second Close() = %v", err)
		}
		if _, err := handle.ReadAt(t.Context(), buf, 0); !errors.Is(err, facetfs.ErrInvalid) {
			t.Fatalf("ReadAt() after close = %v", err)
		}

		if _, _, _, err := backend.Create(t.Context(), facetfs.Request{}, root, "file", facetfs.CreateOptions{Exclusive: true}); !errors.Is(err, facetfs.ErrExists) {
			t.Fatalf("exclusive Create() = %v", err)
		}
		opened, err := backend.Open(t.Context(), facetfs.Request{}, object, facetfs.OpenOptions{Access: facetfs.OpenRead})
		if err != nil {
			t.Fatal(err)
		}
		handle = mutableHandle(t, opened)
		if n, err := handle.ReadAt(t.Context(), buf[:5], 0); err != nil || n != 5 {
			t.Fatalf("reopened ReadAt() = %d, %v", n, err)
		}
		if _, err := handle.WriteAt(t.Context(), []byte("x"), 0); !errors.Is(err, facetfs.ErrAccessDenied) {
			t.Fatalf("read-only handle WriteAt() = %v", err)
		}
		if err := handle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("replace", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		source, sourceHandle := createFile(t, backend, root, "source")
		target, targetHandle := createFile(t, backend, root, "target")
		if _, err := sourceHandle.WriteAt(t.Context(), []byte("source"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := targetHandle.WriteAt(t.Context(), []byte("target"), 0); err != nil {
			t.Fatal(err)
		}
		if err := backend.Rename(t.Context(), facetfs.Request{}, root, "source", root, "target", facetfs.RenameOptions{}); !errors.Is(err, facetfs.ErrExists) {
			t.Fatalf("Rename() without replace = %v", err)
		}
		if err := backend.Rename(t.Context(), facetfs.Request{}, root, "source", root, "target", facetfs.RenameOptions{Replace: true}); err != nil {
			t.Fatal(err)
		}
		found, _, err := backend.Lookup(t.Context(), facetfs.Request{}, root, "target")
		if err != nil {
			t.Fatal(err)
		}
		if found != source {
			t.Fatalf("replacement object = %v, want %v", found, source)
		}
		buf := make([]byte, 6)
		if _, err := targetHandle.ReadAt(t.Context(), buf, 0); err != nil || string(buf) != "target" {
			t.Fatalf("replaced open handle = %q, %v", buf, err)
		}
		if err := sourceHandle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := targetHandle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.GetAttr(t.Context(), facetfs.Request{}, target, facetfs.AttrAll); !errors.Is(err, facetfs.ErrStaleObject) {
			t.Fatalf("replaced object after close = %v", err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		dir, _, err := backend.Mkdir(t.Context(), facetfs.Request{}, root, "dir", facetfs.SetAttr{})
		if err != nil {
			t.Fatal(err)
		}
		_, handle := createFile(t, backend, dir, "file")
		if err := handle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := backend.Remove(t.Context(), facetfs.Request{}, root, "dir", facetfs.RemoveDirectory); !errors.Is(err, facetfs.ErrNotEmpty) {
			t.Fatalf("Remove() non-empty directory = %v", err)
		}
		if err := backend.Remove(t.Context(), facetfs.Request{}, dir, "file", facetfs.RemoveDirectory); !errors.Is(err, facetfs.ErrNotDirectory) {
			t.Fatalf("Remove() file as directory = %v", err)
		}
		if err := backend.Remove(t.Context(), facetfs.Request{}, dir, "file", facetfs.RemoveFile); err != nil {
			t.Fatal(err)
		}
		if err := backend.Remove(t.Context(), facetfs.Request{}, root, "dir", facetfs.RemoveDirectory); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("directories", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		for _, name := range []string{"c", "a", "b"} {
			_, handle := createFile(t, backend, root, name)
			if err := handle.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
		}

		first, err := backend.ReadDir(t.Context(), facetfs.Request{}, root, "", 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(first.Entries) != 2 || first.Entries[0].Name != "a" || first.Entries[1].Name != "b" || first.Next == "" {
			t.Fatalf("first page = %#v", first)
		}
		second, err := backend.ReadDir(t.Context(), facetfs.Request{}, root, first.Next, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(second.Entries) != 1 || second.Entries[0].Name != "c" || second.Next != "" {
			t.Fatalf("second page = %#v", second)
		}
		if _, err := backend.ReadDir(t.Context(), facetfs.Request{}, root, "invalid", 2); !errors.Is(err, facetfs.ErrStaleCursor) {
			t.Fatalf("ReadDir() with invalid cursor = %v", err)
		}

		dir, got, err := backend.Mkdir(t.Context(), facetfs.Request{}, root, "dir", facetfs.SetAttr{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != facetfs.NodeTypeDirectory || got.FileID != dir.NodeID {
			t.Fatalf("Mkdir() = %#v, %#v", dir, got)
		}
		if _, _, err := backend.Lookup(t.Context(), facetfs.Request{}, root, "dir"); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.ReadDir(t.Context(), facetfs.Request{}, root, first.Next, 2); !errors.Is(err, facetfs.ErrStaleCursor) {
			t.Fatalf("ReadDir() with stale cursor = %v", err)
		}
	})

	t.Run("namespace", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		object, handle := createFile(t, backend, root, "old")
		if err := backend.Rename(t.Context(), facetfs.Request{}, root, "old", root, "new", facetfs.RenameOptions{}); err != nil {
			t.Fatal(err)
		}
		found, _, err := backend.Lookup(t.Context(), facetfs.Request{}, root, "new")
		if err != nil {
			t.Fatal(err)
		}
		if found != object {
			t.Fatalf("object changed across rename: %v != %v", found, object)
		}
		if _, _, err := backend.Lookup(t.Context(), facetfs.Request{}, root, "old"); !errors.Is(err, facetfs.ErrNotFound) {
			t.Fatalf("old name lookup = %v", err)
		}

		if err := backend.Remove(t.Context(), facetfs.Request{}, root, "new", facetfs.RemoveFile); err != nil {
			t.Fatal(err)
		}
		if _, err := handle.WriteAt(t.Context(), []byte("open"), 0); err != nil {
			t.Fatalf("write through unlinked handle = %v", err)
		}
		if err := handle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.GetAttr(t.Context(), facetfs.Request{}, object, facetfs.AttrAll); !errors.Is(err, facetfs.ErrStaleObject) {
			t.Fatalf("GetAttr() after final close = %v", err)
		}
	})

	t.Run("links", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		caps, err := backend.Capabilities(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if caps.Symlinks {
			object, got, err := backend.Symlink(t.Context(), facetfs.Request{}, root, "sym", "target", facetfs.SetAttr{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != facetfs.NodeTypeSymlink || got.FileID != object.NodeID {
				t.Fatalf("Symlink() = %#v, %#v", object, got)
			}
			target, err := backend.Readlink(t.Context(), facetfs.Request{}, object)
			if err != nil || target != "target" {
				t.Fatalf("Readlink() = %q, %v", target, err)
			}
		}
		if caps.HardLinks {
			object, handle := createFile(t, backend, root, "one")
			if err := handle.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := backend.Link(t.Context(), facetfs.Request{}, object, root, "two"); err != nil {
				t.Fatal(err)
			}
			linked, got, err := backend.Lookup(t.Context(), facetfs.Request{}, root, "two")
			if err != nil {
				t.Fatal(err)
			}
			if linked != object || got.LinkCount != 2 {
				t.Fatalf("hard link = %#v, %#v", linked, got)
			}
		}
	})

	t.Run("concurrent offset IO", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		_, handle := createFile(t, backend, root, "parallel")
		const workers = 16
		ctx := t.Context()
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := handle.WriteAt(ctx, []byte{byte(i)}, int64(i)); err != nil {
					t.Errorf("WriteAt(%d) = %v", i, err)
				}
			}()
		}
		wg.Wait()
		buf := make([]byte, workers)
		if _, err := handle.ReadAt(t.Context(), buf, 0); err != nil {
			t.Fatal(err)
		}
		for i, value := range buf {
			if value != byte(i) {
				t.Fatalf("byte %d = %d", i, value)
			}
		}
		if err := handle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("errors and cancellation", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		if _, _, err := backend.Lookup(t.Context(), facetfs.Request{}, root, "missing"); !errors.Is(err, facetfs.ErrNotFound) {
			t.Fatalf("Lookup() = %v", err)
		}
		if _, err := backend.ReadDir(t.Context(), facetfs.Request{}, root, "", 0); !errors.Is(err, facetfs.ErrInvalid) {
			t.Fatalf("ReadDir() = %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, _, err := backend.Root(ctx, facetfs.Request{}, "test"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Root() = %v", err)
		}
		if _, err := backend.StatFS(t.Context(), facetfs.Request{}, root); err != nil {
			t.Fatal(err)
		}
		stale := root
		stale.Generation++
		if _, err := backend.GetAttr(t.Context(), facetfs.Request{}, stale, facetfs.AttrAll); !errors.Is(err, facetfs.ErrStaleObject) {
			t.Fatalf("GetAttr() with stale generation = %v", err)
		}
		if _, _, _, err := backend.Create(t.Context(), facetfs.Request{}, root, "bad/name", facetfs.CreateOptions{}); !errors.Is(err, facetfs.ErrInvalid) {
			t.Fatalf("Create() with invalid name = %v", err)
		}
		if _, _, _, err := backend.Create(t.Context(), facetfs.Request{}, root, strings.Repeat("a", 256), facetfs.CreateOptions{}); !errors.Is(err, facetfs.ErrNameTooLong) {
			t.Fatalf("Create() with long name = %v", err)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		object, handle := createFile(t, backend, root, "file")
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		operations := []struct {
			name string
			run  func() error
		}{
			{"capabilities", func() error { _, err := backend.Capabilities(ctx); return err }},
			{"root", func() error { _, _, err := backend.Root(ctx, facetfs.Request{}, "test"); return err }},
			{"lookup", func() error { _, _, err := backend.Lookup(ctx, facetfs.Request{}, root, "file"); return err }},
			{"getattr", func() error { _, err := backend.GetAttr(ctx, facetfs.Request{}, object, facetfs.AttrAll); return err }},
			{"readdir", func() error { _, err := backend.ReadDir(ctx, facetfs.Request{}, root, "", 1); return err }},
			{"open", func() error {
				_, err := backend.Open(ctx, facetfs.Request{}, object, facetfs.OpenOptions{})
				return err
			}},
			{"readlink", func() error { _, err := backend.Readlink(ctx, facetfs.Request{}, object); return err }},
			{"statfs", func() error { _, err := backend.StatFS(ctx, facetfs.Request{}, root); return err }},
			{"create", func() error {
				_, _, _, err := backend.Create(ctx, facetfs.Request{}, root, "new", facetfs.CreateOptions{})
				return err
			}},
			{"mkdir", func() error {
				_, _, err := backend.Mkdir(ctx, facetfs.Request{}, root, "dir", facetfs.SetAttr{})
				return err
			}},
			{"symlink", func() error {
				_, _, err := backend.Symlink(ctx, facetfs.Request{}, root, "sym", "target", facetfs.SetAttr{})
				return err
			}},
			{"link", func() error { return backend.Link(ctx, facetfs.Request{}, object, root, "link") }},
			{"remove", func() error { return backend.Remove(ctx, facetfs.Request{}, root, "file", facetfs.RemoveFile) }},
			{"rename", func() error {
				return backend.Rename(ctx, facetfs.Request{}, root, "file", root, "renamed", facetfs.RenameOptions{})
			}},
			{"setattr", func() error { _, err := backend.SetAttr(ctx, facetfs.Request{}, object, facetfs.SetAttr{}); return err }},
			{"read", func() error { _, err := handle.ReadAt(ctx, nil, 0); return err }},
			{"write", func() error { _, err := handle.WriteAt(ctx, nil, 0); return err }},
			{"flush", func() error { return handle.Flush(ctx, false) }},
			{"handle setattr", func() error { _, err := handle.SetAttr(ctx, facetfs.SetAttr{}); return err }},
			{"close", func() error { return handle.Close(ctx) }},
		}
		for _, operation := range operations {
			t.Run(operation.name, func(t *testing.T) {
				if err := operation.run(); !errors.Is(err, context.Canceled) {
					t.Fatalf("operation error = %v", err)
				}
			})
		}
		if err := handle.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("concurrent namespace", func(t *testing.T) {
		backend := mutableBackend(t, newBackend(t))
		root := backendRoot(t, backend)
		ctx := t.Context()
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				name := fmt.Sprintf("file-%02d", i)
				_, handle, _, err := backend.Create(ctx, facetfs.Request{}, root, name, facetfs.CreateOptions{Exclusive: true})
				if err != nil {
					t.Errorf("Create(%q) = %v", name, err)
					return
				}
				if err := handle.Close(ctx); err != nil {
					t.Errorf("Close(%q) = %v", name, err)
				}
			}()
		}
		wg.Wait()
		page, err := backend.ReadDir(t.Context(), facetfs.Request{}, root, "", 64)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Entries) != 32 {
			t.Fatalf("ReadDir() returned %d entries", len(page.Entries))
		}
	})
}

func backendRoot(t *testing.T, backend facetfs.Backend) facetfs.ObjectRef {
	t.Helper()
	root, got, err := backend.Root(t.Context(), facetfs.Request{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != facetfs.NodeTypeDirectory || got.FileID != root.NodeID || got.Generation != root.Generation {
		t.Fatalf("Root() = %#v, %#v", root, got)
	}
	return root
}

func createFile(t *testing.T, backend facetfs.MutableBackend, parent facetfs.ObjectRef, name string) (facetfs.ObjectRef, facetfs.MutableHandle) {
	t.Helper()
	object, handle, got, err := backend.Create(t.Context(), facetfs.Request{}, parent, name, facetfs.CreateOptions{
		Open: facetfs.OpenOptions{Access: facetfs.OpenRead | facetfs.OpenWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != facetfs.NodeTypeRegular || got.FileID != object.NodeID || handle == nil {
		t.Fatalf("Create() = %#v, %#v, %#v", object, handle, got)
	}
	return object, mutableHandle(t, handle)
}

func mutableBackend(t *testing.T, backend facetfs.Backend) facetfs.MutableBackend {
	t.Helper()
	caps, err := backend.Capabilities(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if caps.ReadOnly {
		t.Skip("read-only backend")
	}
	mutable, ok := backend.(facetfs.MutableBackend)
	if !ok {
		t.Fatal("backend does not implement facetfs.MutableBackend")
	}
	return mutable
}

func mutableHandle(t *testing.T, handle facetfs.Handle) facetfs.MutableHandle {
	t.Helper()
	mutable, ok := handle.(facetfs.MutableHandle)
	if !ok {
		t.Fatal("writable backend returned a handle that does not implement facetfs.MutableHandle")
	}
	return mutable
}
