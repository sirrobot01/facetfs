package facetfs

import "context"

// Backend is the protocol-neutral filesystem contract. Implementations must be
// safe for concurrent use unless they explicitly serialize inside the backend.
type Backend interface {
	Capabilities(context.Context) (Capabilities, error)
	Root(context.Context, Request, string) (ObjectRef, Attr, error)
	Lookup(context.Context, Request, ObjectRef, string) (ObjectRef, Attr, error)
	GetAttr(context.Context, Request, ObjectRef, AttrMask) (Attr, error)
	ReadDir(context.Context, Request, ObjectRef, DirCursor, int) (DirPage, error)
	Open(context.Context, Request, ObjectRef, OpenOptions) (Handle, error)
	Readlink(context.Context, Request, ObjectRef) (string, error)
	StatFS(context.Context, Request, ObjectRef) (FSStat, error)
}

type MutableBackend interface {
	Backend
	Create(context.Context, Request, ObjectRef, string, CreateOptions) (ObjectRef, Handle, Attr, error)
	Mkdir(context.Context, Request, ObjectRef, string, SetAttr) (ObjectRef, Attr, error)
	Symlink(context.Context, Request, ObjectRef, string, string, SetAttr) (ObjectRef, Attr, error)
	Link(context.Context, Request, ObjectRef, ObjectRef, string) error
	Remove(context.Context, Request, ObjectRef, string, RemoveKind) error
	Rename(context.Context, Request, ObjectRef, string, ObjectRef, string, RenameOptions) error
	SetAttr(context.Context, Request, ObjectRef, SetAttr) (Attr, error)
}

type Handle interface {
	ID() string
	Object() ObjectRef
	ReadAt(context.Context, []byte, int64) (int, error)
	Close(context.Context) error
}

type MutableHandle interface {
	Handle
	WriteAt(context.Context, []byte, int64) (int, error)
	Flush(context.Context, bool) error
	SetAttr(context.Context, SetAttr) (Attr, error)
}
