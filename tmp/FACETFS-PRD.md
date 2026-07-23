# FacetFS — Product Requirements and Architecture/System Design

- **Status:** Draft for implementation
- **Document version:** 0.1
- **Date:** 2026-07-23
- **Project type:** Standalone open-source Go module and optional server daemon
- **Working name:** FacetFS
- **Tagline:** One filesystem. Many protocols.
- **Normative language:** MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as requirement levels.

## 1. Executive summary

FacetFS is an embeddable, pure-Go server framework that exposes one filesystem
backend through NFSv4, SMB, SFTP, and WebDAV.

FacetFS is an independent project and Go module. It is designed for use by any
application that implements the FacetFS backend interface.

The central product problem is not implementing four independent file servers.
It is providing one coherent filesystem contract and one shared state engine so
that all four protocol frontends observe compatible namespace, open, locking,
identity, permission, and cache-invalidation semantics.

The first stable release targets:

- NFSv4.0 over TCP, including stateful opens, byte-range locks, leases, grace,
  and reclaim behavior.
- SMB 2.1 and SMB 3.1.1 over Direct TCP, with SMB1 explicitly rejected.
- SFTP version 3 over SSH, suitable for OpenSSH clients and SSHFS.
- WebDAV with read/write collections, conditional requests, ranges, and Class 2
  locking.
- A public Go API for custom backends and embeddable protocol servers.
- A reference local-filesystem backend and a standalone `facetfsd` daemon.
- Static, CGO-free builds.

FacetFS will ship in protocol milestones. Early versions may advertise an
explicit experimental profile. The project MUST NOT claim RFC or Windows
interoperability compliance until the relevant release gate is satisfied.

## 2. Problem statement

Applications that own a virtual or physical filesystem commonly need to expose
the same data to Unix, Windows, media, automation, and browser-oriented clients.
Today they usually embed separate protocol implementations. Each implementation
defines a different filesystem interface and independently handles permissions,
locks, file handles, caching, and errors.

This causes five recurring problems:

1. Backend authors implement the same filesystem operations multiple times.
2. A write through one protocol is not reliably visible through another.
3. Locks and share reservations are enforced within one protocol but ignored by
   the others.
4. Identity and ACL behavior silently changes with the access protocol.
5. Protocol implementations become coupled to one application's storage model.

FacetFS solves this by putting protocol translation at the edge and filesystem
semantics in a shared coordinator.

## 3. Product goals

### 3.1 Primary goals

- Provide a stable, protocol-neutral Go filesystem API designed for network
  file-server semantics rather than only `io/fs` semantics.
- Allow an application to expose the same backend simultaneously over NFSv4,
  SMB, SFTP, and WebDAV.
- Coordinate opens, locks, mutations, and invalidations across protocols.
- Remain pure Go and build with `CGO_ENABLED=0`.
- Be useful as both an embeddable library and a standalone daemon.
- Make supported and unsupported protocol behavior machine-readable and
  precisely documented.
- Default to secure, bounded handling of untrusted network traffic.
- Provide conformance, interoperability, fuzz, and race-test infrastructure as
  first-class project components.

### 3.2 Secondary goals

- Support read-only, read/write, virtual, remote, and local filesystem backends.
- Allow applications to supply authentication, authorization, audit, metrics,
  state persistence, and listener lifecycle integrations.
- Permit protocol frontends to be enabled independently.
- Make future NFSv4.1/v4.2 and additional protocols possible without breaking
  the core backend contract.

### 3.3 Non-goals for v1.0

- NFSv2 or NFSv3.
- NFSv4.1 sessions, NFSv4.2, or pNFS.
- SMB1/CIFS.
- SMB printing, named pipes, domain-controller behavior, DFS namespaces, RDMA,
  SMB over QUIC, or SMB multichannel.
- A shell, terminal, SCP server, or general-purpose SSH daemon. FacetFS exposes
  only the SFTP subsystem.
- A browser UI, file synchronization product, NAS management plane, or storage
  engine.
- Distributed metadata, clustering, active-active failover, or consensus.
- Perfect emulation of every protocol's ACL model on every backend.
- Transparent coherence for mutations made directly behind FacetFS unless the
  backend implements change notification or version detection.
- Depending on application-specific packages or storage models.

## 4. Users and primary use cases

### 4.1 Backend author

A Go developer implements `facetfs.Backend` over a virtual catalog, object
store, database, archive, remote content service, or existing filesystem and
enables one or more protocol servers.

### 4.2 Application embedder

A Go application constructs protocol servers with its own listeners,
authentication provider, logger, metrics sink, and lifecycle context.

### 4.3 Standalone operator

An operator runs `facetfsd`, exports one or more local directories, configures
users and shares, and serves Linux, macOS, Windows, SSHFS, and WebDAV clients.

### 4.4 Protocol client

A client can create, read, modify, rename, and remove a file through one
protocol and observe the result through another, subject to permissions and
client caching rules.

## 5. Product principles

1. **One semantic core.** Protocol handlers do not call backends directly.
2. **Capability truthfulness.** Unsupported behavior is negotiated or rejected;
   it is not silently approximated when approximation can corrupt data.
3. **Stable identity over paths.** Open files and wire handles refer to stable
   object identities, not mutable path strings.
4. **Concurrent I/O uses offsets.** The core API uses `ReadAt` and `WriteAt`, not
   a shared seek cursor.
5. **State is explicit.** Opens, locks, leases, replay caches, and grace periods
   are modeled resources with owners and expiration.
6. **Protocol parsers are hostile-input boundaries.** Length, allocation,
   nesting, and concurrency are bounded before dispatch.
7. **No false compliance.** Every release publishes a tested protocol profile.
8. **Portable core, explicit backend semantics.** The API does not pretend that
   Windows, POSIX, object stores, and virtual catalogs have identical behavior.

## 6. Release profiles

| Profile | Purpose | Required outcome |
|---|---|---|
| `dev` | Wire and backend development | No compatibility promise |
| `experimental` | Mountable by named clients | Exact limitations and required client options documented |
| `compatible` | Routine use with tested clients | All P0 operations, recovery paths, and security defaults pass |
| `conformant` | Standards claim | Normative requirements and selected external suites pass |

Each running frontend MUST expose its profile and capability set through logs,
metrics, and a programmatic inspection API. Experimental profiles MUST NOT be
described as standards-compliant.

## 7. Functional requirements

### 7.1 Core filesystem

- **CORE-001:** A backend MUST expose a stable `NodeID` for the lifetime of an
  object. IDs MUST NOT be derived solely from paths.
- **CORE-002:** A backend MUST return a generation value that changes when an ID
  is reused for a different object.
- **CORE-003:** The API MUST cover lookup, attributes, directory enumeration,
  open, close, read-at, write-at, flush, allocate/truncate, create, mkdir,
  symlink, readlink, link, remove, and rename.
- **CORE-004:** Namespace mutations MUST identify their atomicity and overwrite
  behavior.
- **CORE-005:** Directory enumeration MUST use opaque continuation tokens rather
  than numeric indexes exposed by the backend contract.
- **CORE-006:** Backends MUST publish capabilities at startup. A frontend MUST
  fail startup or disable a feature if required semantics are unavailable.
- **CORE-007:** Read-only backends MUST be supported without implementing write
  methods; mutation attempts return a canonical read-only error.
- **CORE-008:** Context cancellation and deadlines MUST propagate from the wire
  request to the backend operation.
- **CORE-009:** All operations MUST carry an authenticated principal and request
  metadata.
- **CORE-010:** The coordinator MUST serialize conflicting namespace mutations
  without globally serializing unrelated I/O.
- **CORE-011:** Mutations completed through any frontend MUST invalidate shared
  attribute, directory, and data metadata caches before success is returned.
- **CORE-012:** A backend MAY publish external change events. Without them,
  coherence guarantees apply only to operations routed through FacetFS.

### 7.2 Open and lock coordination

- **STATE-001:** The shared state engine MUST own protocol-independent open-file
  records.
- **STATE-002:** SMB share-access reservations, NFS open state, SFTP handles, and
  WebDAV locks MUST be associated with the same `NodeID` namespace.
- **STATE-003:** Byte-range locks MUST detect conflicts across NFS, SMB, and SFTP
  operations where the protocol exposes locking.
- **STATE-004:** WebDAV exclusive write locks MUST conflict with mutations from
  other protocols according to the configured cross-protocol lock policy.
- **STATE-005:** The default policy MUST prioritize data safety: a conflicting
  mandatory lock rejects the operation.
- **STATE-006:** Lock ordering MUST be deterministic. The implementation MUST
  document and test deadlock avoidance.
- **STATE-007:** Disconnect cleanup, lease expiry, explicit close, and server
  shutdown MUST be separate state transitions and idempotent.
- **STATE-008:** Stateful protocol replay detection MUST return the previously
  committed result where required and MUST NOT repeat a mutation.

### 7.3 Identity and authorization

- **AUTH-001:** Protocol authentication MUST resolve to a canonical `Principal`.
- **AUTH-002:** A principal MUST contain a stable subject ID, display name,
  groups, authentication method, and protocol-specific claims.
- **AUTH-003:** Authorization MUST be evaluated on every operation; an open
  handle does not permanently bypass revoked access unless required by the
  negotiated protocol semantics.
- **AUTH-004:** Protocol adapters MUST NOT invent administrator privileges for
  unmapped users.
- **AUTH-005:** Anonymous and guest access MUST be disabled by default.
- **AUTH-006:** Credential comparison MUST be constant-time where applicable.
- **AUTH-007:** Authentication and authorization implementations MUST be
  injectable interfaces.

### 7.4 Metadata and ACLs

- **META-001:** Core attributes MUST include type, size, allocation size,
  owner, group, mode, link count, timestamps, change token, file ID, and
  generation.
- **META-002:** Optional capabilities MUST cover ACLs, extended attributes,
  sparse allocation, filesystem statistics, and change notification.
- **META-003:** Protocol-specific metadata that has no safe backend mapping MUST
  be stored in an optional sidecar `MetadataStore` or reported unsupported.
- **META-004:** The default ACL profile for v1.0 is owner/group/mode plus a
  canonical access check. Full lossless NFSv4-to-Windows ACL round-tripping is a
  post-v1.0 goal.
- **META-005:** A lossy ACL write MUST be rejected unless the operator explicitly
  enables documented lossy mapping.
- **META-006:** Name normalization, case sensitivity, and collision behavior MUST
  be declared per export and MUST remain consistent across frontends.

### 7.5 Exports and shares

- **EXPORT-001:** One FacetFS instance MUST support multiple named exports.
- **EXPORT-002:** Each export MUST bind one backend root, access policy, and
  protocol visibility policy.
- **EXPORT-003:** NFS pseudo-filesystem paths, SMB share names, SFTP roots, and
  WebDAV URL prefixes MUST map to the same export IDs.
- **EXPORT-004:** Export IDs MUST be stable across restart when persistent wire
  handles are enabled.
- **EXPORT-005:** Path traversal, separator ambiguity, reserved-name mapping, and
  Unicode validation MUST be handled before backend dispatch.

## 8. Protocol requirements

### 8.1 NFSv4.0

Normative references are RFC 7530 and its authoritative XDR companion RFC 7531,
including applicable errata and updates.

- Listen on TCP port 2049 by default. UDP, MOUNT, NLM, and rpcbind are not
  required for NFSv4.
- Implement ONC RPC record marking and XDR with bounded decoding.
- Accept NFS minor version 0. Unsupported minor versions return the specified
  minor-version mismatch error.
- Implement the NFSv4 pseudo-filesystem and `COMPOUND` execution model.
- Maintain current and saved file handles per compound request.
- Implement client IDs, open owners, lock owners, sequence IDs, stateids,
  leases, renewal, server grace, and reclaim.
- File handles MUST be opaque, integrity-checked, export-scoped tokens containing
  or resolving to `NodeID` plus generation. They MUST NOT expose host paths.
- Required NFSv4.0 operations MUST be implemented before the frontend is labeled
  conformant. Optional behavior may return `NFS4ERR_NOTSUPP` only where allowed
  by the specification.
- Delegations MUST initially be disabled by never granting them. The server MUST
  still process valid delegation-return behavior defensively.
- `AUTH_SYS` MAY be offered for trusted-network deployments.
- RPCSEC_GSS support is a conformance gate. An experimental AUTH_SYS-only build
  MUST be labeled non-conformant and MUST log a security warning.
- The initial implementation is single-server. Migration, referrals, trunking,
  and transparent failover are deferred.

#### NFSv4.0 acceptance profile

- Mount, unmount, reconnect, and remount with current Linux and macOS clients.
- Pass create/read/write/truncate/rename/link/symlink/remove/readdir workflows.
- Pass overlapping and non-overlapping byte-range lock tests across two clients.
- Survive client disconnect, lease expiry, server restart, grace, and reclaim
  tests without duplicate mutation or stale state reuse.
- Return stable file handles across rename and restart when the backend and state
  store advertise stable-handle support.
- Execute malformed XDR and compound fuzz corpora without panic, unbounded
  allocation, or process termination.

### 8.2 SMB2/SMB3

The normative protocol reference is Microsoft's `[MS-SMB2]` specification.
FacetFS implements the SMB protocol; it is not a Samba implementation.

- Listen on Direct TCP port 445 by default.
- Detect and reject SMB1 negotiation.
- Target SMB 2.1 and SMB 3.1.1 dialects for v1.0. Other SMB2/3 dialects MAY be
  added when their complete negotiated behavior is tested.
- Implement credit accounting and bounded outstanding requests.
- Implement compound request validation and related-operation semantics.
- Implement these command families for v1.0: `NEGOTIATE`, `SESSION_SETUP`,
  `LOGOFF`, `TREE_CONNECT`, `TREE_DISCONNECT`, `CREATE`, `CLOSE`, `FLUSH`,
  `READ`, `WRITE`, `LOCK`, `CANCEL`, `ECHO`, `QUERY_DIRECTORY`, `QUERY_INFO`,
  `SET_INFO`, `CHANGE_NOTIFY`, and required `IOCTL`/oplock-break subsets.
- Support SPNEGO with NTLMv2 for the initial compatible profile. Kerberos is a
  later authentication provider unless promoted by security review.
- Signing MUST be implemented and enabled by default. Operators MAY require it.
- SMB 3.1.1 pre-authentication integrity MUST be implemented before negotiating
  that dialect.
- SMB3 encryption is required for the v1.0 secure profile. A build that does not
  implement it MUST not advertise encryption capability.
- Share modes and delete-on-close MUST be coordinated through the shared state
  engine.
- The first release MUST not grant oplocks or leases until break, timeout, and
  cross-protocol invalidation behavior is implemented. Negotiating no oplock is
  acceptable for the initial compatibility milestone.
- Durable handles, persistent handles, directory leases, multichannel, RDMA,
  QUIC, compression, DFS, named pipes, and printer shares are deferred unless a
  client requires a narrowly documented subset.
- DOS attributes MAY use the metadata sidecar. Alternate data streams are not
  supported in v1.0.

#### SMB acceptance profile

- Connect, authenticate, map a share, and perform file workflows from supported
  Windows, macOS, and Linux clients.
- Pass concurrent create/open/share-mode/delete-on-close cases from the
  `[MS-SMB2]` state model selected for v1.0.
- Reject invalid signatures, replayed messages, invalid credit charges, malformed
  compound offsets, and oversized allocations.
- Preserve byte-exact data under concurrent reads and non-overlapping writes.
- Demonstrate that an SMB share reservation or byte-range lock conflicts with an
  equivalent NFS operation when policy requires it.

### 8.3 SFTP for SSHFS

FacetFS serves SFTP over SSH. SSHFS is a client that mounts an SFTP server; it is
not a separate server-side wire protocol.

- Implement the SSH transport and user-authentication layers through a reviewed
  pure-Go SSH implementation.
- Expose only the `sftp` subsystem by default. Shell, exec, agent forwarding,
  TCP forwarding, and PTY requests MUST be rejected.
- Target SFTP version 3 for OpenSSH and common SSHFS interoperability.
- Implement `OPEN`, `CLOSE`, `READ`, `WRITE`, `LSTAT`, `FSTAT`, `SETSTAT`,
  `FSETSTAT`, `OPENDIR`, `READDIR`, `REMOVE`, `MKDIR`, `RMDIR`, `REALPATH`,
  `STAT`, `RENAME`, `READLINK`, and `SYMLINK`.
- Support the OpenSSH `posix-rename` extension when the backend provides atomic
  replace semantics. `statvfs` and `fsync` extensions are SHOULD requirements.
- Public-key authentication MUST be supported. Password authentication MAY be
  enabled through an injected verifier and MUST be rate-limited.
- Host keys MUST be supplied or persisted; ephemeral host keys require explicit
  development configuration.
- Legacy cryptographic algorithms MUST be disabled by default.
- Each SFTP file handle MUST resolve to a coordinator open record, not directly
  to an OS file descriptor.

#### SFTP acceptance profile

- Pass scripted OpenSSH `sftp` operations and mount workflows using supported
  SSHFS clients.
- Support parallel reads using independent offsets without a shared seek race.
- Reject shell and forwarding requests.
- Correctly clean up handles and locks when an SSH channel or connection closes.

### 8.4 WebDAV

The normative protocol reference is RFC 4918.

- Embed as an `http.Handler` and also support a managed standalone listener.
- Implement `OPTIONS`, `PROPFIND`, `GET`, `HEAD`, `PUT`, `MKCOL`, `DELETE`,
  `COPY`, `MOVE`, `LOCK`, and `UNLOCK`.
- Support byte ranges and conditional requests using ETag, modification time,
  `If-Match`, `If-None-Match`, and the WebDAV `If` header.
- Support WebDAV Class 1 for the first compatible profile and Class 2 locking for
  v1.0.
- Bound `Depth: infinity` traversal by configurable node, time, and response-size
  limits. Limits MUST fail explicitly rather than truncate a successful response.
- Dead properties MUST use the metadata sidecar or be reported unsupported.
- Basic authentication MUST be rejected on plaintext connections unless an
  explicit insecure-development option is set. Bearer, mTLS, and application
  session authentication MUST be injectable.
- TLS MAY be owned by the embedding application or reverse proxy.
- `COPY` and `MOVE` MUST define overwrite and partial-failure behavior. Atomic
  rename is used only when the backend advertises it.

#### WebDAV acceptance profile

- Pass standard create, browse, range-read, overwrite, conditional-write, move,
  copy, lock, and unlock cases.
- Interoperate with at least one CLI client, one Linux client, and one desktop OS
  WebDAV client from the published support matrix.
- Prevent traversal through encoded separators, dot segments, malformed UTF-8,
  and alternate normalization forms.

## 9. Architecture and System Design (ASD)

### 9.1 System context

```text
                              +----------------------+
 Linux/macOS NFS clients ---> | NFSv4.0 frontend     |
 Windows/Linux SMB clients -->| SMB2/3 frontend      |
 SSHFS/OpenSSH clients ------>| SSH + SFTP frontend  |
 WebDAV clients ------------->| WebDAV frontend      |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Request coordinator  |
                              | authz / opens / locks|
                              | cache / invalidation |
                              +----+------------+----+
                                   |            |
                                   v            v
                         +-------------+  +-------------+
                         | Backend     |  | State and   |
                         | filesystem  |  | metadata    |
                         +-------------+  +-------------+
```

No protocol frontend may bypass the request coordinator.

### 9.2 Request path

```text
wire bytes
   |
   v
bounded decoder -> protocol validation -> authenticate -> resolve export
   -> translate operation -> authorize -> coordinate state/locks
   -> backend operation -> commit metadata/state -> invalidate -> encode reply
```

Mutation replies MUST be sent only after the backend result and required shared
state are committed. If a protocol requires replay safety, the reply record MUST
be recoverable before the mutation is acknowledged.

### 9.3 Public package layout

```text
facetfs/
  backend.go          # Backend and Handle contracts
  types.go            # IDs, attributes, requests, capabilities, errors
  server.go           # multi-frontend lifecycle
  export.go           # export and share definitions
  auth/               # principals, authentication and authorization interfaces
  acl/                # canonical access types and mapping helpers
  state/              # state-store interface and standalone implementation
  metadata/           # protocol metadata sidecar interface
  backend/osfs/       # reference local filesystem backend
  backend/memfs/      # deterministic tests and examples
  nfs4/               # embeddable NFSv4 server
  smb/                # embeddable SMB2/3 server
  sftp/               # embeddable SSH/SFTP server
  webdav/             # http.Handler and managed server
  cmd/facetfsd/       # optional standalone daemon
  internal/wire/xdr/  # generated/validated XDR implementation
  internal/wire/smb/  # SMB framing and codecs
  internal/coord/     # coordinator implementation
  internal/testkit/   # protocol fixtures, fake clock, fault injection
```

Only packages intended for embedders are public. Wire codecs and coordinator
internals remain under `internal` until their APIs prove stable.

### 9.4 Core public types

The following API is directional, not frozen. A prototype and two protocol
adapters MUST validate it before v0.1.

```go
package facetfs

type NodeID string

type ObjectRef struct {
    ExportID   string
    NodeID     NodeID
    Generation uint64
}

type Principal struct {
    Subject string
    Name    string
    Groups  []string
    Method  string
    Claims  map[string]string
}

type Request struct {
    Principal Principal
    Protocol  Protocol
    ClientID  string
    SessionID string
    RemoteAddr net.Addr
}

type Capabilities struct {
    ReadOnly             bool
    StableObjectIDs      bool
    PersistentHandles    bool
    AtomicRename         bool
    HardLinks            bool
    Symlinks             bool
    SparseFiles          bool
    ACLs                 bool
    ExtendedAttributes   bool
    ExternalChangeEvents bool
    CaseSensitive        bool
    CasePreserving       bool
}

type Backend interface {
    Capabilities(ctx context.Context) (Capabilities, error)
    Root(ctx context.Context, req Request, exportID string) (ObjectRef, Attr, error)
    Lookup(ctx context.Context, req Request, parent ObjectRef, name string) (ObjectRef, Attr, error)
    GetAttr(ctx context.Context, req Request, object ObjectRef, mask AttrMask) (Attr, error)
    ReadDir(ctx context.Context, req Request, dir ObjectRef, cursor DirCursor, max int) (DirPage, error)

    Open(ctx context.Context, req Request, object ObjectRef, options OpenOptions) (Handle, error)
    Create(ctx context.Context, req Request, parent ObjectRef, name string, options CreateOptions) (ObjectRef, Handle, Attr, error)
    Mkdir(ctx context.Context, req Request, parent ObjectRef, name string, attr SetAttr) (ObjectRef, Attr, error)
    Symlink(ctx context.Context, req Request, parent ObjectRef, name, target string, attr SetAttr) (ObjectRef, Attr, error)
    Readlink(ctx context.Context, req Request, object ObjectRef) (string, error)
    Link(ctx context.Context, req Request, object, newParent ObjectRef, newName string) error
    Remove(ctx context.Context, req Request, parent ObjectRef, name string, expect RemoveKind) error
    Rename(ctx context.Context, req Request, oldParent ObjectRef, oldName string, newParent ObjectRef, newName string, options RenameOptions) error
    SetAttr(ctx context.Context, req Request, object ObjectRef, attr SetAttr) (Attr, error)
    StatFS(ctx context.Context, req Request, object ObjectRef) (FSStat, error)
}

type Handle interface {
    ID() string
    Object() ObjectRef
    ReadAt(ctx context.Context, p []byte, off int64) (int, error)
    WriteAt(ctx context.Context, p []byte, off int64) (int, error)
    Flush(ctx context.Context, stable bool) error
    SetAttr(ctx context.Context, attr SetAttr) (Attr, error)
    Close(ctx context.Context) error
}
```

Design constraints:

- `ObjectRef` identifies namespace objects; `Handle` represents an opened
  resource. Neither is a path.
- `ReadAt`/`WriteAt` allow pipelined protocol requests safely.
- Every method receives `Request`; hidden global user context is prohibited.
- Attribute masks avoid expensive backend calls for data a protocol did not ask
  for.
- `DirCursor` is opaque and integrity-checked. A stale cursor returns a canonical
  stale-cookie error.
- Optional APIs such as ACLs, xattrs, allocation, notifications, and server-side
  copy use capability-specific interfaces discovered through explicit helpers,
  not a single ever-growing base interface.

### 9.5 Canonical errors

FacetFS MUST define errors by semantics, not by one protocol's numeric codes.

```text
NotFound, Exists, NotDirectory, IsDirectory, NotEmpty,
AccessDenied, AuthenticationRequired, ReadOnly, Invalid,
NameTooLong, NoSpace, Quota, TooManyOpenFiles, Busy,
WouldBlock, LockConflict, StaleObject, StaleCursor,
NotSupported, CrossDevice, IO, Corrupt, Canceled, Timeout
```

Each frontend owns a total mapping from canonical errors to its wire status. An
unmapped error is a test failure. Internal error messages MUST NOT be returned to
clients unless debug mode is explicitly enabled.

### 9.6 Coordinator components

```text
Coordinator
  +-- ExportResolver       stable export and root mapping
  +-- Authorizer           operation-level access decisions
  +-- OpenTable            access/share reservations and lifecycle
  +-- RangeLockManager     interval locks by ObjectRef
  +-- LeaseManager         NFS leases and future SMB leases
  +-- ReplayCache          exactly-once/replay-required results
  +-- NamespaceLocker      ordered mutation locks
  +-- MetadataCache        attributes and directory pages
  +-- InvalidationBus      cross-protocol coherence events
  +-- StateStore           optional persistent recovery state
  +-- MetadataStore        protocol metadata without backend representation
  +-- AuditSink            security and mutation records
```

State tables MUST be sharded by stable object or owner identity. A single global
mutex is prohibited on read/write hot paths.

### 9.7 Open lifecycle

```text
requested -> authorized -> reserved -> backend-open -> active
     |             |           |            |
     +-----------> failed <-----+------------+

active -> closing -> backend-closed -> released
   |          |
   |          +--> cleanup-pending -> released
   +--> disconnected -> reclaimable/expired -> released
```

Reservation and backend-open form a compensating transaction: if backend open
fails, the reservation is released. Close is idempotent. A failed backend close
does not leave a permanent share reservation; cleanup is retried and surfaced to
observability.

### 9.8 Mutation ordering

Namespace locks use the tuple `(ExportID, NodeID, Generation)`. Multi-directory
operations acquire locks in lexicographic tuple order. Rename locks the source
directory, target directory, and affected objects in canonical order. No backend
call may be made while waiting to acquire another namespace lock.

The coordinator provides operation atomicity only to the extent advertised by
the backend. For example, a backend without atomic replace cannot truthfully
implement an atomic SMB rename or WebDAV MOVE; that capability is rejected or
documented as non-atomic in an experimental profile.

### 9.9 Cross-protocol coherence

```text
SMB WRITE
   -> coordinator writes backend
   -> advances object change token
   -> invalidates attribute/data metadata
   -> emits ObjectChanged(ObjectRef, range)
      -> NFS attribute cache generation advances
      -> WebDAV ETag changes
      -> SMB change notifications complete
      -> SFTP next STAT observes new attributes
```

FacetFS does not control client-side cache duration. Protocol cache grants such
as future SMB leases or NFS delegations MUST not be issued until invalidation and
recall are implemented across all enabled frontends.

### 9.10 Persistence and recovery

`StateStore` MUST support atomic compare-and-set or transaction semantics for:

- server instance identity and boot epoch;
- stable export IDs and file-handle secrets;
- replay records required across restart;
- NFS client/open/lock reclaim metadata;
- persistent metadata sidecar references.

The library MUST offer an in-memory store for tests and ephemeral use. The daemon
MUST offer a crash-safe local persistent store. Its concrete database is an
implementation decision validated by corruption and power-loss tests; it is not
part of the public API.

On unclean restart, stateful frontends enter protocol-appropriate recovery:

```text
boot -> load epoch/state -> recovery/grace -> reject conflicting new state
     -> accept valid reclaim -> grace ends -> purge unreclaimed state -> normal
```

### 9.11 Memory and resource bounds

Every listener MUST support limits for:

- accepted and authenticated connections;
- sessions per principal and source address;
- open handles and locks;
- outstanding requests and decoded compound operations;
- request, response, path, attribute, and directory-page sizes;
- authentication failures and negotiation time;
- idle, operation, and shutdown deadlines.

Decoders MUST validate integer overflow and remaining-buffer length before
allocation. Request-controlled allocation MUST have a configured upper bound.

### 9.12 Embedding API

```go
backend := osfs.New("/srv/media")

srv, err := facetfs.New(facetfs.Config{
    StateStore: state,
    Authorizer: authorizer,
    Exports: []facetfs.Export{{
        ID:      "media",
        Name:    "Media",
        Backend: backend,
    }},
})
if err != nil { /* handle */ }

srv.Add(nfs4.New(nfs4.Options{Addr: ":2049"}))
srv.Add(smb.New(smb.Options{Addr: ":445"}))
srv.Add(sftp.New(sftp.Options{Addr: ":2022", HostKeys: keys}))
srv.Add(webdav.New(webdav.Options{Prefix: "/dav"}))

if err := srv.Serve(ctx); err != nil { /* handle */ }
```

The actual API MAY change during prototyping, but the following behavior is
required:

- construction validates backend capabilities against enabled frontends;
- caller-owned and FacetFS-owned listeners are both possible;
- `Serve` fails atomically if a required frontend cannot start;
- graceful shutdown stops accepts, drains bounded in-flight work, flushes state,
  and closes handles;
- one frontend failure is observable and follows a configured fail-fast policy.

### 9.13 Standalone daemon

`facetfsd` is a thin composition layer, not the source of core behavior.

```yaml
state_dir: /var/lib/facetfs

exports:
  - id: media
    name: Media
    path: /srv/media
    read_only: false
    protocols: [nfs4, smb, sftp, webdav]

listeners:
  nfs4:  { address: ":2049", security: [sys] }
  smb:   { address: ":445", require_signing: true }
  sftp:  { address: ":2022", host_key_files: ["/etc/facetfs/ssh_host_ed25519_key"] }
  webdav: { address: ":8080", prefix: "/dav" }
```

This sample is illustrative. Secrets MUST support file, environment-provider, or
application-provider references and MUST NOT be logged.

## 10. Security requirements

- **SEC-001:** Threat model assumes unauthenticated clients can reach listeners.
- **SEC-002:** All wire decoders MUST be continuously fuzzed.
- **SEC-003:** No panic caused by client input may escape a connection boundary.
- **SEC-004:** Panic recovery MUST close the affected request/connection and emit
  an audit event; it is not a substitute for parser correctness.
- **SEC-005:** Authentication failures MUST be rate-limited without creating an
  unbounded per-source map.
- **SEC-006:** File handles and cursors MUST be unforgeable or validated against
  server-side state.
- **SEC-007:** Logs and metrics MUST exclude passwords, session keys, bearer
  tokens, raw NTLM material, and private claims.
- **SEC-008:** Default configurations MUST not enable anonymous write access.
- **SEC-009:** SMB signing is on by default; SMB1 is always disabled.
- **SEC-010:** WebDAV Basic auth requires TLS except in explicit development mode.
- **SEC-011:** SSH uses a reviewed modern algorithm policy and persistent host
  identity.
- **SEC-012:** NFS AUTH_SYS documentation MUST state that IDs are asserted by the
  client and require a trusted network. RPCSEC_GSS is required for the secure
  NFS profile.
- **SEC-013:** Dependency scanning, `govulncheck`, static analysis, secret
  scanning, and a security reporting policy are release requirements.
- **SEC-014:** Resource exhaustion tests MUST cover slow clients, lock floods,
  open floods, deep directory traversal, and oversized compound requests.

## 11. Non-functional requirements

### 11.1 Portability

- `CGO_ENABLED=0 go test ./...` MUST pass.
- Release artifacts MUST be static Go binaries where supported.
- Linux amd64 and arm64 are required server platforms for v1.0.
- macOS and Windows MUST compile; server support becomes guaranteed only after
  platform-specific filesystem semantics pass the published test matrix.
- The project supports the current and previous stable Go release unless a
  documented security requirement forces a newer minimum.

### 11.2 Correctness

- All packages MUST pass `go test -race` on supported CI platforms.
- Mutation and state-machine tests MUST use a deterministic fake clock and fault
  injection.
- Each protocol status/error mapping MUST have table-driven coverage.
- Cross-protocol tests MUST operate on the same backend instance.
- Acknowledged stable writes MUST survive the documented crash model.

### 11.3 Performance

Initial performance gates are measured against the reference local backend on a
published test host:

- Sequential 1 MiB reads through one frontend SHOULD achieve at least 80% of the
  same backend's direct `ReadAt` throughput after protocol encryption costs are
  separated in reporting.
- The coordinator SHOULD add less than 1 ms p95 in-process overhead to cached
  metadata operations under 100 concurrent clients.
- Independent files MUST scale across available CPU cores without a global lock
  bottleneck.
- Streaming memory MUST be bounded by configured connection and request windows;
  file size MUST not affect resident memory linearly.
- Benchmarks report throughput, latency percentiles, allocations, connections,
  outstanding operations, and lock contention. A single headline throughput
  number is insufficient.

These thresholds are engineering gates, not universal end-to-end guarantees.
They may be revised using reproducible benchmark evidence.

### 11.4 Reliability

- Graceful shutdown MUST complete or time out deterministically.
- Connection loss MUST release non-reclaimable resources.
- Backends returning short reads/writes, partial errors, cancellation, or delayed
  completion MUST not corrupt protocol state.
- Startup MUST detect corrupt or incompatible persistent state and fail safely;
  it MUST NOT silently discard recovery state.
- State and metadata schemas require versioning and forward migration tests.

### 11.5 Observability

The library MUST use injected structured logging and optional metrics/tracing
interfaces. Required signals include:

- connections, sessions, authenticated principals, and open handles;
- requests, latency, bytes, and errors by protocol and operation;
- active locks, conflicts, lease expiry, reclaim, and replay hits;
- backend latency and failure class;
- rejected requests by validation or resource limit;
- cache hits, invalidations, and stale-object detection;
- startup profile and negotiated protocol capabilities.

High-cardinality file paths, user IDs, client IDs, and session IDs MUST not be
metric labels by default.

## 12. Testing and verification strategy

### 12.1 Test layers

1. **Codec tests:** golden frames, invalid lengths, truncation, endianness,
   alignment, compound offsets, and round trips.
2. **State-machine tests:** model opens, locks, leases, replay, disconnect,
   expiry, grace, and reclaim with deterministic scheduling.
3. **Backend contract suite:** every backend implementation runs the same
   semantics and capability tests.
4. **Frontend integration:** real clients exercise a memory backend and OS
   backend.
5. **Cross-protocol tests:** mutate through one frontend and assert behavior
   through every other enabled frontend.
6. **Fault injection:** fail before/after backend mutation, state commit,
   invalidation, reply encoding, disconnect, and restart.
7. **Fuzzing:** every unauthenticated decoder and state transition entry point.
8. **Soak/load:** long-running mixed workloads with leaks, races, and resource
   ceilings monitored.

### 12.2 Required client matrix

Exact versions are pinned in CI/release documentation rather than this PRD.

| Frontend | Required clients |
|---|---|
| NFSv4.0 | Linux kernel NFS client; macOS NFS client; one independent NFS test tool |
| SMB | Windows client; Linux `mount.cifs`/smbclient; macOS SMB client |
| SFTP | OpenSSH `sftp`; one SSHFS implementation; one Go test client |
| WebDAV | `curl`; one Linux CLI/mount client; macOS or Windows native client |

### 12.3 Cross-protocol scenarios

- Create via SMB, read via NFS, rename via SFTP, delete via WebDAV.
- Hold an SMB deny-write open and attempt NFS/SFTP/WebDAV writes.
- Hold an NFS byte-range lock and attempt an overlapping SMB lock/write.
- Modify through WebDAV and observe changed NFS attributes and SMB notification.
- Rename a file while it is open through all four protocols; verify documented
  handle behavior and no path-based aliasing.
- Restart during active NFS state and SMB sessions; verify each protocol's
  documented recovery behavior.
- Exhaust configured handles/locks/connections and verify bounded, reversible
  failure.

### 12.4 Definition of done for a protocol operation

An operation is not complete until it has:

- bounded decode and validation;
- canonical request and error mapping;
- authentication and authorization hooks;
- coordinator/state integration;
- backend contract coverage;
- golden success and failure packets;
- malformed-input fuzz seeds;
- real-client interoperability coverage;
- metrics and structured debug logging;
- user-facing support documentation.

## 13. Delivery plan

### Phase 0 — Repository and engineering foundation

Deliverables:

- Independent `facetfs` repository and Go module.
- License, contribution guide, security policy, CI, fuzz jobs, release process.
- Memory backend, fake clock, fault injector, codec conventions, and testkit.

Exit gate:

- Static build, race CI, fuzz smoke tests, and backend contract skeleton pass.

### Phase 1 — Core contract and coordinator

Deliverables:

- Backend, handle, capabilities, canonical attributes, and canonical errors.
- Export resolver, principal/authorizer, open table, range lock manager,
  namespace locking, invalidation bus, and in-memory state store.
- Reference memory and OS backends.

Exit gate:

- Backend contract suite passes for both backends.
- Cross-protocol-neutral state model passes model and race tests.
- Core API has been exercised by two prototype adapters before freezing v0.1.

### Phase 2 — WebDAV and SFTP validation frontends

Deliverables:

- WebDAV Class 1 compatible profile.
- SSH/SFTP v3 compatible profile with public-key authentication.
- Shared mutation, handle, identity, and error behavior proven through both.

Exit gate:

- Supported clients complete read/write workflows.
- Cross-frontend create/read/rename/delete and conflict tests pass.
- No frontend-specific methods have leaked into the base backend interface
  without a capability design review.

### Phase 3 — NFSv4.0 primary frontend

Deliverables:

- ONC RPC/XDR, pseudo-filesystem, COMPOUND engine, required operations.
- Client/open/lock owner state, stateids, leases, grace, and reclaim.
- Stable opaque file handles and persistent server identity.
- AUTH_SYS experimental profile, followed by RPCSEC_GSS secure/conformance
  profile.

Exit gate:

- Required client matrix and recovery scenarios pass.
- Every required NFSv4.0 operation is implemented or the release remains labeled
  experimental with an exact exception list.
- Normative RFC checklist is reviewed independently.

### Phase 4 — SMB2/3 frontend

Deliverables:

- Direct TCP transport, negotiation, sessions, trees, files, directories,
  signing, credits, compound requests, NTLMv2, and selected SMB3 security.
- Shared share-mode, byte-range lock, delete-on-close, and change-notify behavior.

Exit gate:

- Windows/Linux/macOS client matrix passes.
- SMB1 downgrade is rejected.
- Signing, pre-auth integrity, replay, credit, malformed compound, and resource
  exhaustion security tests pass.
- Unsupported capabilities are never advertised.

### Phase 5 — v1.0 hardening

Deliverables:

- WebDAV Class 2 locking.
- SMB3 encryption secure profile.
- Persistent local state store and recovery tooling.
- Full four-protocol cross-coherence suite.
- Performance, soak, compatibility, security, and documentation releases.

Exit gate:

- All P0 requirements pass on the published support matrix.
- No known data-loss, authentication-bypass, handle-forgery, replay, or
  unbounded-allocation defect remains open.
- Independent protocol/security review findings are resolved or documented as
  release blockers.

## 14. Priorities

### P0 — required for v1.0

- Pure-Go core and four protocol frontends.
- Reference local backend and embeddable API.
- Stable identities and opaque handles.
- Cross-protocol opens, byte-range locks, and invalidation.
- Secure protocol negotiation and authentication hooks.
- Persistent NFS recovery state.
- Fuzz, race, fault, interoperability, and cross-protocol test suites.
- Exact support matrix and non-compliance disclosures.

### P1 — target shortly after v1.0

- Kerberos authentication for SMB if not included in v1.0.
- SMB leases/oplocks with cross-protocol recall.
- Rich canonical ACL mapping and inheritance.
- Additional SFTP OpenSSH extensions.
- Backend external-change watchers.
- Administration and diagnostic CLI commands.

### P2 — future

- NFSv4.1 sessions and v4.2 features.
- SMB durable handles and multichannel.
- Cluster-safe state and failover.
- Object-storage reference backend.
- Additional frontends such as FTP are considered only after core semantics and
  maintenance cost are evaluated.

## 15. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Scope across two large stateful protocols | Multi-year delay | Ship profile-based phases; WebDAV/SFTP validate core early |
| Incorrect shared abstraction | Backend churn and protocol leaks | Prototype two frontends before v0.1 API freeze; capability interfaces |
| ACL semantic mismatch | Access bypass or permission loss | Conservative v1 profile; reject lossy writes by default |
| Lock semantic mismatch | Corruption or surprising denial | One coordinator; documented mandatory-lock policy; cross-protocol tests |
| Unstable backend IDs | Stale handles access wrong file | Generation checks; fail capability validation; persistent ID adapter |
| Client-specific undocumented behavior | Mount failures | Packet fixtures, real-client CI, explicit compatibility matrix |
| Parser vulnerability | Remote compromise or DoS | Bounded decoders, fuzzing, resource ceilings, independent review |
| Recovery/replay defect | Duplicate or lost mutation | Write-ahead replay state where required; crash-point fault injection |
| Pure-Go security feature gaps | Delayed conformance | Audit dependencies early; isolate crypto/auth providers; no false claims |
| External backend mutation | Stale caches | Change-event capability or conservative TTL; document coherence boundary |
| Performance lost to common coordinator | Poor throughput | Offset I/O, sharded state, bounded zero-copy paths, continuous benchmarks |

## 16. Success metrics

FacetFS v1.0 succeeds when:

- A third-party Go application can implement a backend using only public API and
  pass the backend contract suite.
- The same export is concurrently usable through all four protocols.
- The required client matrix passes without undocumented mount flags.
- Cross-protocol lock and mutation scenarios are deterministic and data-correct.
- All wire decoders run continuously under fuzzing without unresolved crashers.
- Static race-enabled and CGO-disabled CI passes.
- Performance gates are met or revised with public reproducible evidence.
- Protocol support claims match the normative checklist and published profile.

Adoption metrics such as stars or downloads are observed but are not substitutes
for protocol correctness.

## 17. Open decisions before implementation

These decisions block API or security work and require explicit maintainer
decisions before the affected work begins:

1. **License:** Apache-2.0 is recommended for explicit patent terms; final choice
   remains with the maintainer.
2. **Module path and organization:** reserve the selected GitHub organization or
   owner repository before publishing imports.
3. **Persistent store:** select after crash, transaction, static-build, and
   maintenance evaluation.
4. **NFS RPCSEC_GSS implementation:** dependency versus in-project implementation,
   supported mechanisms, and credential mapping.
5. **SMB authentication implementation:** NTLMv2/SPNEGO dependency and secret
   storage interface.
6. **Canonical ACL model:** exact access-mask and inheritance representation for
   the post-v1 rich ACL profile.
7. **OS backend stable IDs:** platform-specific generation and restart guarantees.
8. **Compliance suites:** select redistributable automation and define which
   external suites are required versus advisory.

Decisions that do not block the first core prototype should not delay Phase 1.

## 18. Normative and design references

- [RFC 7530 — Network File System Version 4 Protocol](https://www.rfc-editor.org/info/rfc7530/)
- [RFC 7531 — NFSv4.0 XDR Description](https://www.rfc-editor.org/info/rfc7531/)
- [Microsoft MS-SMB2 — SMB Protocol Versions 2 and 3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962)
- [RFC 4253 — SSH Transport Layer Protocol](https://www.rfc-editor.org/info/rfc4253/)
- [RFC 4252 — SSH Authentication Protocol](https://www.rfc-editor.org/info/rfc4252/)
- [IETF Secure Shell File Transfer draft](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
- [OpenSSH `sftp-server`](https://man.openbsd.org/sftp-server.8)
- [RFC 4918 — WebDAV](https://www.rfc-editor.org/info/rfc4918/)

## 19. Product boundary statement

FacetFS owns protocol serving, shared network-filesystem semantics, and the
backend contract. It does not own application catalogs, domain-specific
business logic, download managers, media logic, storage-provider APIs, or an
embedding application's data model.

Applications integrate through an adapter that implements the FacetFS backend
contract:

```text
Application storage adapter -> FacetFS Backend interface
                            -> NFSv4 / SMB / SFTP / WebDAV
```

FacetFS public packages MUST NOT import application-specific packages. The
dependency direction always points from the embedding application to FacetFS.
