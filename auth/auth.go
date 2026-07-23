// Package auth provides common FacetFS authorization policies.
package auth

import "github.com/sirrobot01/facetfs"

type Action = facetfs.Action
type Check = facetfs.AccessCheck
type Authorizer = facetfs.Authorizer
type AuthorizerFunc = facetfs.AuthorizerFunc

const (
	ActionRoot     = facetfs.ActionRoot
	ActionLookup   = facetfs.ActionLookup
	ActionGetAttr  = facetfs.ActionGetAttr
	ActionReadDir  = facetfs.ActionReadDir
	ActionRead     = facetfs.ActionRead
	ActionWrite    = facetfs.ActionWrite
	ActionCreate   = facetfs.ActionCreate
	ActionMkdir    = facetfs.ActionMkdir
	ActionSymlink  = facetfs.ActionSymlink
	ActionReadlink = facetfs.ActionReadlink
	ActionLink     = facetfs.ActionLink
	ActionRemove   = facetfs.ActionRemove
	ActionRename   = facetfs.ActionRename
	ActionSetAttr  = facetfs.ActionSetAttr
	ActionStatFS   = facetfs.ActionStatFS
)
