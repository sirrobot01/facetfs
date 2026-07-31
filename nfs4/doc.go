// Package nfs4 provides an experimental embeddable NFSv4.0 server that serves
// a facetfs.FileSystem on caller-supplied net.Listener or net.Conn values. The
// caller owns the transport, credentials, and export policy.
//
// Byte-range locks are advisory: they coordinate cooperating NFS clients but
// do not prevent direct filesystem access or I/O through another protocol.
// Filehandles and protocol state are volatile across server restarts. AUTH_SYS
// credentials must therefore be used only on a trusted transport or behind an
// authentication boundary supplied by the caller.
package nfs4
