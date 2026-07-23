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
