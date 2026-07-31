// Package nfs4 provides an embeddable NFSv4.0 server that serves
// a facetfs.FileSystem on caller-supplied net.Listener or net.Conn values. The
// caller owns the transport, credentials, and export policy.
//
// Byte-range locks are advisory: they coordinate cooperating NFS clients but
// do not prevent direct filesystem access or I/O through another protocol.
// Protocol state is volatile across server restarts, and so are filehandles
// unless a fixed Server.HandleKey is supplied (with Server.ResolveLongHandle
// covering paths too long to embed in a handle). AUTH_SYS credentials must be
// used only on a trusted transport or behind an authentication boundary
// supplied by the caller.
//
// Read delegations (Server.ReadDelegations) are off by default. A delegation
// promises a client that the file will not change without a recall first, and
// this server can only recall what it sees: a write through another protocol
// or by the application itself recalls nothing and a delegated client would
// keep serving stale data. Enable delegations only when this NFS server is
// the only writer.
package nfs4
