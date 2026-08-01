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
| `nfs4`   | NFSv4.0        | a `net.Listener`                       | usable      |
| `smb`    | SMB2/SMB3      | a `net.Listener` and NT-hash lookup    | experimental |

The `facetcache` package is not a protocol. It wraps a slow `FileSystem` and
serves reads from local disk, so every protocol package benefits at once.

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

Three implementations ship with the module:

- `facetfs.OpenDir("/srv/data")` serves a native directory tree from a handle
  it holds open. Use it in a server: holding the tree open makes a metadata
  operation many times cheaper. Close it when you are done.
- `facetfs.Dir("/srv/data")` serves the same tree without holding a handle,
  which is convenient in a test but reopens the tree on every operation.
- `facetfs.NewMemFS()` is an in-memory filesystem for tests and prototypes.

Both reach the tree through `os.Root`, so symbolic links cannot escape it.

Optional interfaces unlock protocol features:

| Interface   | Methods                    | Unlocks                                  |
| ----------- | -------------------------- | ---------------------------------------- |
| `SymlinkFS` | `Symlink, Readlink, Lstat` | symlinks over SFTP, WebDAV, and NFS      |
| `SetStatFS` | `Chmod, Chtimes, Truncate` | SFTP `setstat`, NFS `SETATTR`, SMB `SET_INFO` |
| `StatVFSFS` | `StatVFS`                  | SFTP `statvfs`, NFS and SMB space attributes |
| `LinkFS`    | `Link`                     | NFS `LINK` and the `link_support` attribute |
| `RemoveFS`  | `Remove`                   | safe directory removal over WebDAV and SMB |

A `File` may also implement `io.ReaderAt` and `io.WriterAt`, which let SFTP and
NFS and SMB serve positioned reads and writes in parallel, and `Sync() error`,
which backs NFS `COMMIT`, SMB `FLUSH`, and stable writes.

A filesystem without an interface still works. The protocol packages refuse
only the requests that need it.

## WebDAV

`webdav.Handler` is an `http.Handler`. Mount it on your own server, behind
your own authentication:

```go
served, err := facetfs.OpenDir("/srv/data")
if err != nil {
    log.Fatal(err)
}
defer served.Close()

handler := &webdav.Handler{
    Prefix:     "/dav",
    FileSystem: served,
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
server := &sftp.Server{FileSystem: served} // from facetfs.OpenDir

// Inside your SSH session-channel loop:
if err := server.Serve(ctx, channel); err != nil {
    log.Printf("sftp session: %v", err)
}
```

See [examples/sftp](./examples/sftp) for a complete program with host keys and
`authorized_keys` verification.

## SMB2/SMB3

`smb.Server` serves one SMB share over a listener you bind. The application
looks up an NT hash for each user; the package performs NTLMv2, derives the
session key, and signs the session.

```go
server := &smb.Server{
    FileSystem:    served,
    Authenticator: credentials, // implements smb.Authenticator
    ShareName:     "share",
}
listener, err := net.Listen("tcp", "127.0.0.1:1445")
if err != nil {
    log.Fatal(err)
}
log.Fatal(server.Serve(ctx, listener))
```

The package serves SMB 2.1 and 3.1.1. Signing prevents undetected changes but
does not hide file contents; SMB encryption is not implemented, so use a
trusted network. Byte-range locks are advisory. The implementation remains
experimental until its Windows, macOS, and Linux client acceptance matrix has
passed. See [examples/smb](./examples/smb).

## NFSv4.0

`nfs4.Server` serves NFSv4.0 on a listener you bind. Operating-system clients
mount it directly. No portmapper or mountd is needed.

```go
server := &nfs4.Server{FileSystem: served} // from facetfs.OpenDir
listener, err := net.Listen("tcp", "127.0.0.1:20490")
if err != nil {
    log.Fatal(err)
}
log.Fatal(server.Serve(ctx, listener))
```

Mount it from macOS or Linux:

```sh
sudo mount -t nfs -o vers=4.0,tcp,port=20490 localhost:/ /tmp/nfsmnt
```

NFSv4 carries only AUTH_SYS identities, so serve it on a trusted network or
behind your own authentication boundary. Filehandles and protocol state do
not survive a restart, and byte-range locks are advisory. Read delegations
are off by default and safe only when the NFS server is the only writer. See
[examples/nfs](./examples/nfs).

## Caching

`facetcache.Cache` wraps a slow backend — HTTP, S3, a debrid service — and
serves reads from local disk. Compose it between the backend and a protocol
server:

```go
cache := &facetcache.Cache{
    Backend: backend,            // any facetfs.FileSystem
    Dir:     "/var/cache/facet", // the cache owns this directory
}
fsys, err := cache.FileSystem()
if err != nil {
    log.Fatal(err)
}
defer cache.Close()
srv := &nfs4.Server{FileSystem: fsys}
```

The wrapper keeps two caches. An attribute cache answers `Stat` and `Lstat`
from memory with a short TTL; NFS costs several stats per read, so this cache
matters more than the bytes against a high-latency backend. A content cache
stores file bytes in one sparse file per object, tracks exactly which ranges
are present, fills misses from the backend with read-ahead, and deduplicates
concurrent fetches. Content persists across restarts and is validated against
the backend by a size and mtime fingerprint.

Writes go through: the backend must acknowledge a write before the cache
stores it. The wrapper exposes exactly the optional interfaces the backend
implements, and cached files keep `io.ReaderAt`, so servers keep their
parallel read paths. A janitor bounds the cache by size (`MaxBytes`) and age
(`MaxAge`); on Linux it also punches holes behind the read head of open
streams when whole-file eviction cannot reach the budget.

Do not cache a backend that something else mutates. The cache invalidates on
its own mutations only; an external write serves stale attributes until the
TTL expires and stale content until a cold open sees the fingerprint change.

A warm read costs the same as a direct `pread` and allocates nothing. A warm
`Stat` is a map lookup. Do not wrap a local directory: the kernel page cache
already serves those reads, and a disk cache in front of a disk is overhead.

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

Run the SMB example on an unprivileged loopback port:

```sh
mkdir -p ./shared
FACETFS_USER=demo FACETFS_PASSWORD=change-me \
  go run ./examples/smb -root ./shared

sudo mount -t cifs -o vers=3.1.1,port=1445,user=demo \
  //127.0.0.1/share /mnt/facetfs
```

Explorer normally connects only to TCP port 445; bind the example to `:445`
on a test host when running the Windows acceptance profile.

The examples are starting points. Production applications must provide durable
host keys, TLS, authorization policy, timeouts, and logging.

## Development

The project requires Go 1.26 and builds without CGO.

```sh
make check
make race
make bench-protocols
```

`make bench-protocols` compares warm metadata, read, and overwrite operations
over NFSv4, SFTP, and WebDAV on loopback. All three serve the same in-memory
filesystem, and connection setup, SSH, TLS, and authentication are excluded.
The results therefore show steady-state protocol-path overhead, not disk or
WAN performance. Read and write rows report throughput as well as latency;
run with `-count=5` and compare medians before drawing conclusions from small
differences.

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
