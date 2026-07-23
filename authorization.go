package facetfs

import "context"

type Action string

const (
	ActionRoot     Action = "root"
	ActionLookup   Action = "lookup"
	ActionGetAttr  Action = "getattr"
	ActionReadDir  Action = "readdir"
	ActionRead     Action = "read"
	ActionWrite    Action = "write"
	ActionCreate   Action = "create"
	ActionMkdir    Action = "mkdir"
	ActionSymlink  Action = "symlink"
	ActionReadlink Action = "readlink"
	ActionLink     Action = "link"
	ActionRemove   Action = "remove"
	ActionRename   Action = "rename"
	ActionSetAttr  Action = "setattr"
	ActionStatFS   Action = "statfs"
	ActionLock     Action = "lock"
)

type AccessCheck struct {
	ExportID  string
	Action    Action
	Object    ObjectRef
	Parent    ObjectRef
	Name      string
	NewParent ObjectRef
	NewName   string
}

type Authorizer interface {
	Authorize(context.Context, Request, AccessCheck) error
}

type AuthorizerFunc func(context.Context, Request, AccessCheck) error

func (f AuthorizerFunc) Authorize(ctx context.Context, request Request, check AccessCheck) error {
	return f(ctx, request, check)
}
