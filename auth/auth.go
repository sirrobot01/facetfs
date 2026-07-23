// Package auth defines protocol-neutral authorization hooks.
package auth

import (
	"context"

	"github.com/sirrobot01/facetfs"
)

// Action is a canonical filesystem operation checked by an Authorizer.
type Action string

const (
	ActionLookup Action = "lookup"
	ActionRead   Action = "read"
	ActionWrite  Action = "write"
	ActionCreate Action = "create"
	ActionRemove Action = "remove"
	ActionRename Action = "rename"
	ActionLock   Action = "lock"
)

// Check contains the operation and objects involved in an authorization
// decision. Name is set for namespace operations.
type Check struct {
	Action Action
	Object facetfs.ObjectRef
	Parent facetfs.ObjectRef
	Name   string
}

// Authorizer evaluates access for every operation. A nil error allows access;
// denial should use facetfs.ErrAccessDenied.
type Authorizer interface {
	Authorize(context.Context, facetfs.Request, Check) error
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(context.Context, facetfs.Request, Check) error

func (f AuthorizerFunc) Authorize(ctx context.Context, req facetfs.Request, check Check) error {
	return f(ctx, req, check)
}
