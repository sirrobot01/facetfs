# FacetFS

**Embeddable file-protocol handlers for Go.**

FacetFS is a set of thin protocol packages in the style of
`golang.org/x/net/webdav`. You implement one small filesystem interface. Each
package serves it over one protocol. You own the transport, the listener, and
authentication. FacetFS only speaks the protocol.

There is no server framework, no daemon, and no shared runtime. Each protocol
package is independent. Import only what you use.

| Package  | Protocol       | You provide                            | Status      |
| -------- | -------------- | -------------------------------------- | ----------- |
| `webdav` | WebDAV (HTTP)  | an `http.Server` and auth middleware   | usable      |
| `sftp`   | SFTP           | an SSH server and an accepted channel  | usable      |
| `nfs4`   | NFSv4.0        | a `net.Listener`                       | planned     |
| `smb`    | SMB2/SMB3      | a `net.Listener`                       | planned     |

## The filesystem interface

The root package defines one path-based contract. Implement it once. Serve it
over any protocol.

```go
type FileSystem interface {
    Mkdir(ctx context.Context, name string, perm fs.FileMode) error
    OpenFile(ctx context.Context, name string, flag int, perm fs.FileMode) (File, error)
    RemoveAll(ctx context.Context, name string) error
    Rename(ctx context.Context, oldName, newName string) error
    Stat(ctx context.Context, name string) (fs.FileInfo, error)
}
```

Return errors that satisfy `errors.Is` against the `io/fs` sentinels:
`fs.ErrNotExist`, `fs.ErrExist`, `fs.ErrPermission`, and `fs.ErrInvalid`.

Two implementations ship with the module:

- `facetfs.Dir("/srv/data")` serves a native directory tree. It uses `os.Root`,
  so symbolic links cannot escape the tree.
- `facetfs.NewMemFS()` is an in-memory filesystem for tests and prototypes.

Optional interfaces unlock protocol features:

| Interface   | Methods                      | Unlocks                        |
| ----------- | ---------------------------- | ------------------------------ |
| `SymlinkFS` | `Symlink, Readlink, Lstat`   | symlinks over SFTP and WebDAV  |
| `SetStatFS` | `Chmod, Chtimes, Truncate`   | SFTP `setstat`                 |
| `StatVFSFS` | `StatVFS`                    | SFTP `statvfs`                 |

A filesystem without an interface still works. The protocol packages refuse
only the requests that need it.

## WebDAV

`webdav.Handler` is an `http.Handler`. Mount it on your own server, behind
your own authentication:

```go
handler := &webdav.Handler{
    Prefix:     "/dav",
    FileSystem: facetfs.Dir("/srv/data"),
    LockSystem: webdav.NewMemLS(), // omit for class 1 only
}
http.Handle("/dav/", yourAuthMiddleware(handler))
log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
```

The handler implements RFC 4918 class 1 and 2, with exclusive Depth-0 write
locks. See [examples/webdav](./examples/webdav) for a complete program with
basic authentication and TLS.

## SFTP

`sftp.Server` serves one already-authenticated stream. Run your own SSH server
with `golang.org/x/crypto/ssh`. When a session channel requests the `sftp`
subsystem, pass the channel to `Serve`:

```go
server := &sftp.Server{FileSystem: facetfs.Dir("/srv/data")}

// Inside your SSH session-channel loop:
if err := server.Serve(ctx, channel); err != nil {
    log.Printf("sftp session: %v", err)
}
```

See [examples/sftp](./examples/sftp) for a complete program with host keys and
`authorized_keys` verification.

## Examples

Run the loopback WebDAV example:

```sh
mkdir -p ./shared
FACETFS_USER=demo FACETFS_PASSWORD=change-me \
  go run ./examples/webdav -root ./shared

curl -u demo:change-me -T ./README.md http://127.0.0.1:8080/dav/README.md
curl -u demo:change-me http://127.0.0.1:8080/dav/README.md
```

Plaintext mode is restricted to loopback. Supply `-tls-cert` and `-tls-key`
for a TLS listener.

Run the SFTP example:

```sh
mkdir -p ./shared
ssh-keygen -t ed25519 -N '' -f ./facetfs_host_key
cp ~/.ssh/id_ed25519.pub ./facetfs_authorized_keys

go run ./examples/sftp \
  -root ./shared \
  -host-key ./facetfs_host_key \
  -authorized-keys ./facetfs_authorized_keys

sftp -P 2022 127.0.0.1
```

The examples are starting points. Production applications must provide durable
host keys, TLS, authorization policy, timeouts, and logging.

## Development

The project requires Go 1.26 and builds without CGO.

```sh
make check
make race
```

## Goals

- Pure Go with no CGO requirement
- Thin, independent, embeddable protocol packages
- One filesystem contract shared by every protocol
- Bounded wire handling designed for untrusted input
- Interoperability tests using real clients

The `FileSystem` contract is frozen as of v0.1. Optional capability
interfaces may be added in later releases; existing interfaces do not change.

## License

[MIT License](./LICENSE)
