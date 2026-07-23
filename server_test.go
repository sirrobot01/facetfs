package facetfs

import (
	"context"
	"testing"
)

type stubBackend struct {
	caps Capabilities
}

type baseBackend struct{ Backend }

func (b stubBackend) Capabilities(context.Context) (Capabilities, error) { return b.caps, nil }
func (stubBackend) Root(context.Context, Request, string) (ObjectRef, Attr, error) {
	return ObjectRef{}, Attr{}, ErrNotSupported
}
func (stubBackend) Lookup(context.Context, Request, ObjectRef, string) (ObjectRef, Attr, error) {
	return ObjectRef{}, Attr{}, ErrNotSupported
}
func (stubBackend) GetAttr(context.Context, Request, ObjectRef, AttrMask) (Attr, error) {
	return Attr{}, ErrNotSupported
}
func (stubBackend) ReadDir(context.Context, Request, ObjectRef, DirCursor, int) (DirPage, error) {
	return DirPage{}, ErrNotSupported
}
func (stubBackend) Open(context.Context, Request, ObjectRef, OpenOptions) (Handle, error) {
	return nil, ErrNotSupported
}
func (stubBackend) Create(context.Context, Request, ObjectRef, string, CreateOptions) (ObjectRef, Handle, Attr, error) {
	return ObjectRef{}, nil, Attr{}, ErrNotSupported
}
func (stubBackend) Mkdir(context.Context, Request, ObjectRef, string, SetAttr) (ObjectRef, Attr, error) {
	return ObjectRef{}, Attr{}, ErrNotSupported
}
func (stubBackend) Symlink(context.Context, Request, ObjectRef, string, string, SetAttr) (ObjectRef, Attr, error) {
	return ObjectRef{}, Attr{}, ErrNotSupported
}
func (stubBackend) Readlink(context.Context, Request, ObjectRef) (string, error) {
	return "", ErrNotSupported
}
func (stubBackend) Link(context.Context, Request, ObjectRef, ObjectRef, string) error {
	return ErrNotSupported
}
func (stubBackend) Remove(context.Context, Request, ObjectRef, string, RemoveKind) error {
	return ErrNotSupported
}
func (stubBackend) Rename(context.Context, Request, ObjectRef, string, ObjectRef, string, RenameOptions) error {
	return ErrNotSupported
}
func (stubBackend) SetAttr(context.Context, Request, ObjectRef, SetAttr) (Attr, error) {
	return Attr{}, ErrNotSupported
}
func (stubBackend) StatFS(context.Context, Request, ObjectRef) (FSStat, error) {
	return FSStat{}, ErrNotSupported
}

func TestNewValidatesAndSnapshotsExports(t *testing.T) {
	t.Parallel()
	backend := stubBackend{caps: Capabilities{StableObjectIDs: true, ReadOnly: true}}
	server, err := New(t.Context(), Config{Exports: []Export{{
		ID: "media", Name: "Media", Backend: backend, Protocols: []Protocol{ProtocolWebDAV},
	}}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	exports := server.Exports()
	if len(exports) != 1 || !exports[0].ReadOnly {
		t.Fatalf("Exports() = %#v, want one read-only export", exports)
	}
	exports[0].Protocols[0] = ProtocolSMB
	if server.Exports()[0].Protocols[0] != ProtocolWebDAV {
		t.Fatal("Exports() returned mutable server configuration")
	}
	export, ok := server.Export("media")
	if !ok || !export.Supports(ProtocolWebDAV) || export.Supports(ProtocolSFTP) {
		t.Fatalf("Export() = %#v, %v", export, ok)
	}
	export.Protocols[0] = ProtocolSMB
	current, ok := server.Export("media")
	if !ok || current.Protocols[0] != ProtocolWebDAV {
		t.Fatal("Export() returned mutable server configuration")
	}
	caps, ok := server.Capabilities("media")
	if !ok || !caps.StableObjectIDs {
		t.Fatalf("Capabilities() = %#v, %v", caps, ok)
	}
}

func TestNewAcceptsReadOnlyBackend(t *testing.T) {
	t.Parallel()
	backend := baseBackend{Backend: stubBackend{caps: Capabilities{ReadOnly: true, StableObjectIDs: true}}}
	if _, err := New(t.Context(), Config{Exports: []Export{{ID: "data", Name: "Data", Backend: backend}}}); err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsIncompleteWritableBackend(t *testing.T) {
	t.Parallel()
	backend := baseBackend{Backend: stubBackend{caps: Capabilities{StableObjectIDs: true}}}
	if _, err := New(t.Context(), Config{Exports: []Export{{ID: "data", Name: "Data", Backend: backend}}}); err == nil {
		t.Fatal("New() accepted a writable backend without mutation support")
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	stable := stubBackend{caps: Capabilities{StableObjectIDs: true}}
	unstable := stubBackend{}

	tests := []struct {
		name    string
		exports []Export
	}{
		{name: "empty"},
		{name: "invalid ID", exports: []Export{{ID: "bad/id", Name: "Bad", Backend: stable}}},
		{name: "empty name", exports: []Export{{ID: "bad", Backend: stable}}},
		{name: "unstable IDs", exports: []Export{{ID: "bad", Name: "Bad", Backend: unstable}}},
		{name: "unknown protocol", exports: []Export{{ID: "bad", Name: "Bad", Backend: stable, Protocols: []Protocol{"ftp"}}}},
		{name: "duplicate ID", exports: []Export{
			{ID: "same", Name: "One", Backend: stable},
			{ID: "same", Name: "Two", Backend: stable},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(t.Context(), Config{Exports: test.exports}); err == nil {
				t.Fatal("New() unexpectedly succeeded")
			}
		})
	}
}
