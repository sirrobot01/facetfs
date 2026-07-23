# FacetFS

**One filesystem. Many protocols.**

FacetFS is an embeddable, pure-Go server framework for exposing a filesystem
through multiple network protocols:

- NFSv4
- SMB2/SMB3
- SFTP for SSHFS
- WebDAV

FacetFS is being built around a protocol-neutral backend API and one coordinator
for file handles, opens, locks, identity, permissions, and cache invalidation.
Applications will implement the backend once and choose which protocols to
serve.

> [!IMPORTANT]
> The core runtime, reference backends, WebDAV handler, and SSH/SFTP server are
> implemented. NFSv4 and SMB are not implemented yet.

## Development

The project requires Go 1.26.2 and supports static, CGO-disabled builds.

```sh
make check
make build
./bin/facetfsd -version
```

## Usage

FacetFS applications assemble four pieces:

1. a backend such as `backend/osfs` or `backend/memfs`;
2. one or more exports;
3. an application-owned authorizer;
4. a WebDAV or SFTP frontend with its authentication callback.

The default authorizer denies access, so applications must provide an explicit
authorization policy. Frontend authentication establishes a `Principal`; the
shared authorizer then decides which filesystem operations that principal may
perform.

### WebDAV

The WebDAV frontend is an `http.Handler`, so it can be mounted in an existing
HTTP server or behind a reverse proxy:

```go
handler, err := webdav.New(runtime, webdav.Options{
    ExportID:     "data",
    Prefix:       "/dav",
    Authenticate: authenticateRequest,
})
if err != nil {
    return err
}

httpServer := &http.Server{
    Addr:              ":8443",
    Handler:           handler,
    ReadHeaderTimeout: 10 * time.Second,
}
return httpServer.ListenAndServeTLS("cert.pem", "key.pem")
```

`Authenticate` is application-defined and can establish identities from Basic
authentication, bearer tokens, mTLS, or an existing session. Plaintext Basic
authentication is rejected unless `AllowInsecureBasic` is explicitly enabled.

### SFTP

The SFTP frontend requires caller-supplied host keys and a public-key verifier:

```go
server, err := sftp.New(runtime, sftp.Options{
    ExportID: "data",
    HostKeys: hostKeys,
    AuthenticatePublicKey: authenticatePublicKey,
})
if err != nil {
    return err
}

listener, err := net.Listen("tcp", "127.0.0.1:2022")
if err != nil {
    return err
}
return server.Serve(ctx, listener)
```

Shell, exec, PTY, agent-forwarding, and TCP-forwarding requests are rejected.
Only the SFTP subsystem is served.

## Examples

The examples export a local directory through the reference OS backend.

Run the loopback WebDAV example:

```sh
mkdir -p ./shared
FACETFS_USER=demo FACETFS_PASSWORD=change-me \
  go run ./examples/webdav -root ./shared

curl -u demo:change-me -T ./README.md http://127.0.0.1:8080/dav/README.md
curl -u demo:change-me http://127.0.0.1:8080/dav/README.md
```

Plaintext mode is restricted to loopback. Supply `-tls-cert` and `-tls-key` for
a TLS listener.

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

These programs are starting points for embedding. Production applications
should provide durable host keys, TLS, authorization policy, operational
timeouts, and logging appropriate to their environment.

## Goals

- Pure Go with no CGO requirement
- Embeddable protocol servers and an optional standalone daemon
- Stable, capability-driven backend interfaces
- Cross-protocol locking and namespace coherence
- Bounded wire decoders designed for untrusted input
- Interoperability tests using real operating-system clients

## Current status

The repository currently includes:

- core backend, handle, request, attribute, capability, and canonical-error
  contracts;
- in-memory and local-filesystem backends with reusable contract tests;
- export validation and capability snapshots;
- shared open reservations, byte-range locks, namespace locking, state,
  authorization, and change notifications;
- a bounded WebDAV handler for file, collection, range, conditional, copy,
  move, and property workflows;
- an SSH/SFTP v3 server with public-key authentication, subsystem isolation,
  coordinated handles, symlinks, POSIX rename, and filesystem statistics;
- static-build, vet, test, and race-test automation.

APIs and protocol profiles are not yet stable. NFSv4 and SMB packages remain
placeholders.

## License

[MIT License](./LICENSE)
