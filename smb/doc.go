// Package smb provides an embeddable SMB2/SMB3 server that serves a
// facetfs.FileSystem on caller-supplied net.Listener or net.Conn values. The
// caller owns the transport, the credential store, and the share policy.
//
// Experimental: the protocol and race suites pass, but the Windows, macOS,
// and Linux acceptance profile has not yet been completed. Test the clients
// you intend to support before deploying it.
//
// The package serves dialects 2.1 and 3.1.1 over direct TCP. It answers the
// SMB1 multi-protocol negotiate that Windows Explorer and the macOS Finder
// open a connection with, by stepping the client up to SMB2; it implements
// nothing else of SMB1. It signs
// messages but does not encrypt them, so the transport is not confidential:
// serve it on a trusted network. It grants no oplock and no lease, and its
// byte-range locks are advisory, so they coordinate cooperating SMB clients
// but do not prevent access through another protocol.
//
// The server exports one disk share. It implements session setup, tree and
// handle lifetime, create/read/write/flush/close, share modes, byte-range
// locks, directory enumeration, metadata queries and changes, and negotiate
// validation. Oplocks, leases, durable handles, alternate data streams,
// named pipes, ACL storage, and encryption are intentionally unsupported.
//
// Authentication is NTLMv2. SMB derives the key that signs every message from
// that exchange, so the package runs it and the application supplies the
// secret through an Authenticator. The application therefore keeps its
// credential store, and the package keeps the protocol.
package smb
