package nfs4

// Constants transcribed from RFC 7530 (NFSv4.0) and RFC 7531 (XDR), and the
// ONC RPC constants from RFC 5531.

const (
	nfsProgram   = 100003
	nfsVersion   = 4
	procNull     = 0
	procCompound = 1

	rpcVersion = 2
	msgCall    = 0
	msgReply   = 1

	replyAccepted = 0
	replyDenied   = 1

	acceptSuccess      = 0
	acceptProgUnavail  = 1
	acceptProgMismatch = 2
	acceptProcUnavail  = 3
	acceptGarbageArgs  = 4

	rejectRPCMismatch = 0
	rejectAuthError   = 1

	authBadCred = 1

	authNone = 0
	authSys  = 1
)

type nfsStat uint32

const (
	nfs4OK                   nfsStat = 0
	nfs4ErrPerm              nfsStat = 1
	nfs4ErrNoEnt             nfsStat = 2
	nfs4ErrIO                nfsStat = 5
	nfs4ErrNXIO              nfsStat = 6
	nfs4ErrAccess            nfsStat = 13
	nfs4ErrExist             nfsStat = 17
	nfs4ErrXDev              nfsStat = 18
	nfs4ErrNotDir            nfsStat = 20
	nfs4ErrIsDir             nfsStat = 21
	nfs4ErrInval             nfsStat = 22
	nfs4ErrFBig              nfsStat = 27
	nfs4ErrNoSpc             nfsStat = 28
	nfs4ErrROFS              nfsStat = 30
	nfs4ErrMLink             nfsStat = 31
	nfs4ErrNameTooLong       nfsStat = 63
	nfs4ErrNotEmpty          nfsStat = 66
	nfs4ErrDQuot             nfsStat = 69
	nfs4ErrStale             nfsStat = 70
	nfs4ErrBadHandle         nfsStat = 10001
	nfs4ErrBadCookie         nfsStat = 10003
	nfs4ErrNotSupp           nfsStat = 10004
	nfs4ErrTooSmall          nfsStat = 10005
	nfs4ErrServerFault       nfsStat = 10006
	nfs4ErrBadType           nfsStat = 10007
	nfs4ErrDelay             nfsStat = 10008
	nfs4ErrSame              nfsStat = 10009
	nfs4ErrDenied            nfsStat = 10010
	nfs4ErrExpired           nfsStat = 10011
	nfs4ErrLocked            nfsStat = 10012
	nfs4ErrGrace             nfsStat = 10013
	nfs4ErrFHExpired         nfsStat = 10014
	nfs4ErrShareDenied       nfsStat = 10015
	nfs4ErrWrongSec          nfsStat = 10016
	nfs4ErrClidInUse         nfsStat = 10017
	nfs4ErrResource          nfsStat = 10018
	nfs4ErrMoved             nfsStat = 10019
	nfs4ErrNoFilehandle      nfsStat = 10020
	nfs4ErrMinorVersMismatch nfsStat = 10021
	nfs4ErrStaleClientID     nfsStat = 10022
	nfs4ErrStaleStateID      nfsStat = 10023
	nfs4ErrOldStateID        nfsStat = 10024
	nfs4ErrBadStateID        nfsStat = 10025
	nfs4ErrBadSeqID          nfsStat = 10026
	nfs4ErrNotSame           nfsStat = 10027
	nfs4ErrLockRange         nfsStat = 10028
	nfs4ErrSymlink           nfsStat = 10029
	nfs4ErrRestoreFH         nfsStat = 10030
	nfs4ErrLeaseMoved        nfsStat = 10031
	nfs4ErrAttrNotSupp       nfsStat = 10032
	nfs4ErrNoGrace           nfsStat = 10033
	nfs4ErrReclaimBad        nfsStat = 10034
	nfs4ErrReclaimConflict   nfsStat = 10035
	nfs4ErrBadXDR            nfsStat = 10036
	nfs4ErrLocksHeld         nfsStat = 10037
	nfs4ErrOpenMode          nfsStat = 10038
	nfs4ErrBadOwner          nfsStat = 10039
	nfs4ErrBadChar           nfsStat = 10040
	nfs4ErrBadName           nfsStat = 10041
	nfs4ErrBadRange          nfsStat = 10042
	nfs4ErrLockNotSupp       nfsStat = 10043
	nfs4ErrOpIllegal         nfsStat = 10044
	nfs4ErrDeadlock          nfsStat = 10045
	nfs4ErrFileOpen          nfsStat = 10046
	nfs4ErrAdminRevoked      nfsStat = 10047
	nfs4ErrCBPathDown        nfsStat = 10048
)

const (
	opAccess             = 3
	opClose              = 4
	opCommit             = 5
	opCreate             = 6
	opDelegPurge         = 7
	opDelegReturn        = 8
	opGetAttr            = 9
	opGetFH              = 10
	opLink               = 11
	opLock               = 12
	opLockT              = 13
	opLockU              = 14
	opLookup             = 15
	opLookupP            = 16
	opNVerify            = 17
	opOpen               = 18
	opOpenAttr           = 19
	opOpenConfirm        = 20
	opOpenDowngrade      = 21
	opPutFH              = 22
	opPutPubFH           = 23
	opPutRootFH          = 24
	opRead               = 25
	opReadDir            = 26
	opReadLink           = 27
	opRemove             = 28
	opRename             = 29
	opRenew              = 30
	opRestoreFH          = 31
	opSaveFH             = 32
	opSecInfo            = 33
	opSetAttr            = 34
	opSetClientID        = 35
	opSetClientIDConfirm = 36
	opVerify             = 37
	opWrite              = 38
	opReleaseLockOwner   = 39
	opIllegal            = 10044
)

// fattr4 attribute numbers (RFC 7530 §17).
const (
	attrSupportedAttrs  = 0
	attrType            = 1
	attrFHExpireType    = 2
	attrChange          = 3
	attrSize            = 4
	attrLinkSupport     = 5
	attrSymlinkSupport  = 6
	attrNamedAttr       = 7
	attrFSID            = 8
	attrUniqueHandles   = 9
	attrLeaseTime       = 10
	attrRdattrError     = 11
	attrACLSupport      = 13
	attrCanSetTime      = 15
	attrCaseInsensitive = 16
	attrCasePreserving  = 17
	attrChownRestricted = 18
	attrFilehandle      = 19
	attrFileID          = 20
	attrFilesAvail      = 21
	attrFilesFree       = 22
	attrFilesTotal      = 23
	attrHomogeneous     = 26
	attrMaxFileSize     = 27
	attrMaxLink         = 28
	attrMaxName         = 29
	attrMaxRead         = 30
	attrMaxWrite        = 31
	attrMode            = 33
	attrNoTrunc         = 34
	attrNumLinks        = 35
	attrOwner           = 36
	attrOwnerGroup      = 37
	attrRawDev          = 41
	attrSpaceAvail      = 42
	attrSpaceFree       = 43
	attrSpaceTotal      = 44
	attrSpaceUsed       = 45
	attrTimeAccess      = 47
	attrTimeAccessSet   = 48
	attrTimeDelta       = 51
	attrTimeMetadata    = 52
	attrTimeModify      = 53
	attrTimeModifySet   = 54
	attrMountedOnFileID = 55
)

// nfs_ftype4.
const (
	nf4Reg  = 1
	nf4Dir  = 2
	nf4Blk  = 3
	nf4Chr  = 4
	nf4Lnk  = 5
	nf4Sock = 6
	nf4Fifo = 7
)

const fh4VolatileAny = 2

const (
	maxCompoundOps = 128
	maxTagBytes    = 1024
	maxInflight    = 16
	// maxCachedDirEntries bounds the entries held across all the directory
	// listings clients are paging through.
	maxCachedDirEntries = 1 << 17
	// One client's state is bounded so that a client cannot grow the server
	// without limit. Each open also holds a file open, so the bound on opens
	// is what keeps a client from exhausting file descriptors.
	maxOpensPerClient  = 1 << 12
	maxOwnersPerClient = 1 << 12
	maxLockRanges      = 1 << 12
	// maxExclusiveCreates bounds the remembered exclusive-create verifiers.
	maxExclusiveCreates = 1 << 12
	maxNameBytes        = 255
	maxLinkData         = 4096
	maxCredBytes        = 400
	maxAuthSysGids      = 16
	maxFHBytes          = 128
)
