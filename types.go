package facetfs

import (
	"io/fs"
	"net"
	"time"
)

// Protocol identifies the frontend through which a request arrived.
type Protocol string

const (
	ProtocolNFS4   Protocol = "nfs4"
	ProtocolSMB    Protocol = "smb"
	ProtocolSFTP   Protocol = "sftp"
	ProtocolWebDAV Protocol = "webdav"
)

// NodeID is a backend-provided stable object identifier. It must not be
// derived solely from a mutable path.
type NodeID string

// ObjectRef identifies an object within an export. Generation changes whenever
// a NodeID is reused for a different object.
type ObjectRef struct {
	ExportID   string
	NodeID     NodeID
	Generation uint64
}

// Principal is the protocol-neutral identity established by authentication.
type Principal struct {
	Subject string
	Name    string
	Groups  []string
	Method  string
	Claims  map[string]string
}

// Request carries authenticated identity and connection metadata to every
// backend operation.
type Request struct {
	Principal  Principal
	Protocol   Protocol
	ClientID   string
	SessionID  string
	RemoteAddr net.Addr
}

// NodeType describes the kind of a filesystem object.
type NodeType uint8

const (
	NodeTypeUnknown NodeType = iota
	NodeTypeRegular
	NodeTypeDirectory
	NodeTypeSymlink
)

// Attr contains protocol-neutral object metadata.
type Attr struct {
	Type           NodeType
	Size           int64
	AllocationSize int64
	Owner          string
	Group          string
	Mode           fs.FileMode
	LinkCount      uint32
	AccessedAt     time.Time
	ModifiedAt     time.Time
	ChangedAt      time.Time
	CreatedAt      time.Time
	ChangeToken    string
	FileID         NodeID
	Generation     uint64
}

// AttrMask lets callers avoid requesting metadata that is expensive for a
// backend to produce.
type AttrMask uint64

const (
	AttrType AttrMask = 1 << iota
	AttrSize
	AttrAllocationSize
	AttrOwner
	AttrGroup
	AttrMode
	AttrLinkCount
	AttrAccessedAt
	AttrModifiedAt
	AttrChangedAt
	AttrCreatedAt
	AttrChangeToken
	AttrFileID
	AttrGeneration

	AttrAll = AttrType | AttrSize | AttrAllocationSize | AttrOwner | AttrGroup |
		AttrMode | AttrLinkCount | AttrAccessedAt | AttrModifiedAt |
		AttrChangedAt | AttrCreatedAt | AttrChangeToken | AttrFileID |
		AttrGeneration
)

// SetAttr contains only attributes selected by non-nil fields.
type SetAttr struct {
	Size       *int64
	Owner      *string
	Group      *string
	Mode       *fs.FileMode
	AccessedAt *time.Time
	ModifiedAt *time.Time
}

// DirCursor is an opaque continuation token issued by a backend.
type DirCursor string

// DirEntry is one result in a directory page.
type DirEntry struct {
	Name   string
	Object ObjectRef
	Attr   Attr
}

// DirPage is a bounded page of directory entries. Next is empty when there are
// no more entries.
type DirPage struct {
	Entries []DirEntry
	Next    DirCursor
}

// OpenAccess describes operations requested on an open handle.
type OpenAccess uint8

const (
	OpenRead OpenAccess = 1 << iota
	OpenWrite
	OpenDelete
)

// ShareAccess describes operations that other opens may perform concurrently.
type ShareAccess uint8

const (
	ShareRead ShareAccess = 1 << iota
	ShareWrite
	ShareDelete
)

// OpenOptions contains protocol-neutral access and sharing requirements.
type OpenOptions struct {
	Access OpenAccess
	Share  ShareAccess
}

// CreateOptions controls object creation and the returned open handle.
type CreateOptions struct {
	Open      OpenOptions
	Attr      SetAttr
	Exclusive bool
}

// RemoveKind constrains the kind of object that may be removed.
type RemoveKind uint8

const (
	RemoveAny RemoveKind = iota
	RemoveFile
	RemoveDirectory
)

// RenameOptions declares replacement behavior for a rename operation.
type RenameOptions struct {
	Replace bool
}

// FSStat reports capacity information for the filesystem containing an object.
type FSStat struct {
	TotalBytes uint64
	FreeBytes  uint64
	AvailBytes uint64
	TotalFiles uint64
	FreeFiles  uint64
	NameMax    uint64
}

// Capabilities declares semantics the backend can truthfully provide.
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
