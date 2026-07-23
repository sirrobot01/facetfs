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
> The repository is at the Phase 0 foundation milestone. The core contracts
> compile, but no network frontend serves traffic yet.

## Development

The project requires Go 1.26.2. The baseline is dependency-free and must remain
compatible with static, CGO-disabled builds.

```sh
make check
make build
./bin/facetfsd -version
```

## Target embedding API

The following illustrates the intended API. Frontend constructors and serving
lifecycle will be implemented in later milestones.

```go
srv, err := facetfs.New(facetfs.Config{
    Exports: []facetfs.Export{{
        ID:      "data",
        Name:    "Data",
        Backend: backend,
    }},
})
if err != nil {
    return err
}

srv.Add(nfs4.New(nfs4.Options{Addr: ":2049"}))
srv.Add(smb.New(smb.Options{Addr: ":445"}))
srv.Add(sftp.New(sftp.Options{Addr: ":2022"}))
srv.Add(webdav.New(webdav.Options{Addr: ":8080"}))

return srv.Serve(ctx)
```

## Goals

- Pure Go with no CGO requirement
- Embeddable protocol servers and an optional standalone daemon
- Stable, capability-driven backend interfaces
- Cross-protocol locking and namespace coherence
- Bounded wire decoders designed for untrusted input
- Interoperability tests using real operating-system clients

## Current status

The initial repository foundation includes:

- core backend, handle, request, attribute, capability, and canonical-error
  contracts;
- export validation and capability snapshots;
- package boundaries for the coordinator, reference backends, state,
  metadata, wire codecs, frontends, and daemon;
- static-build, vet, test, and race-test automation.

APIs and protocol profiles are not yet stable. The project currently has no
protocol compliance claim.

## License

[MIT License](./LICENSE)
