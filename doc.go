// Package facetfs defines a small path-based filesystem contract and ships
// embeddable protocol handlers that serve it. The webdav subpackage serves a
// FileSystem over HTTP. The sftp subpackage serves a FileSystem on an
// authenticated SSH channel. The caller owns the transport, the listener, and
// authentication.
//
// Implementations return errors that satisfy errors.Is against the io/fs
// sentinels: fs.ErrNotExist, fs.ErrExist, fs.ErrPermission, and
// fs.ErrInvalid. Dir serves a native directory tree. NewMemFS returns an
// in-memory filesystem for tests and prototypes.
//
// The FileSystem contract is frozen as of v0.1. Optional capability
// interfaces may be added in later releases; existing interfaces do not
// change.
package facetfs
