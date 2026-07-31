package smb

// Constants transcribed from [MS-SMB2] and [MS-ERREF].

// SMB2 commands.
const (
	cmdNegotiate      = 0x0000
	cmdSessionSetup   = 0x0001
	cmdLogoff         = 0x0002
	cmdTreeConnect    = 0x0003
	cmdTreeDisconnect = 0x0004
	cmdCreate         = 0x0005
	cmdClose          = 0x0006
	cmdFlush          = 0x0007
	cmdRead           = 0x0008
	cmdWrite          = 0x0009
	cmdLock           = 0x000A
	cmdIOCtl          = 0x000B
	cmdCancel         = 0x000C
	cmdEcho           = 0x000D
	cmdQueryDirectory = 0x000E
	cmdChangeNotify   = 0x000F
	cmdQueryInfo      = 0x0010
	cmdSetInfo        = 0x0011
	cmdOplockBreak    = 0x0012
	cmdCount          = 0x0013
)

// Header flags.
const (
	flagServerToRedir   = 0x00000001
	flagAsyncCommand    = 0x00000002
	flagRelatedOps      = 0x00000004
	flagSigned          = 0x00000008
	flagDFSOperation    = 0x10000000
	flagReplayOperation = 0x20000000
)

// Dialect revisions. Only the two the package serves are named; the rest are
// recognized so that a negotiation can pick between them. The wildcard is the
// answer to an SMB1 multi-protocol NEGOTIATE: it tells the client to
// negotiate again in SMB2 ([MS-SMB2] section 3.3.5.3.1).
const (
	dialect202          = 0x0202
	dialect210          = 0x0210
	dialect300          = 0x0300
	dialect302          = 0x0302
	dialect311          = 0x0311
	dialectSMB2Wildcard = 0x02FF
)

// SMB1, recognized only far enough to answer the multi-protocol NEGOTIATE.
// The server parses the dialect list of that one message and nothing else.
const (
	smb1HeaderSize   = 32
	smb1CmdNegotiate = 0x72
	// smb1MinNegotiate is a header, a word count, and a byte count.
	smb1MinNegotiate = smb1HeaderSize + 3
	// smb1DialectWildcard in an SMB1 dialect list asks for the step-up to
	// any SMB2 dialect.
	smb1DialectWildcard = "SMB 2.???"
)

// Negotiate security modes.
const (
	signingEnabled  = 0x0001
	signingRequired = 0x0002
)

// Global capabilities. The server advertises large MTU only: it implements
// none of the others, and advertising one obliges it to serve the feature.
const (
	capDFS               = 0x00000001
	capLeasing           = 0x00000002
	capLargeMTU          = 0x00000004
	capMultiChannel      = 0x00000008
	capPersistentHandles = 0x00000010
	capDirectoryLeasing  = 0x00000020
	capEncryption        = 0x00000040
)

// Negotiate context types.
const (
	contextPreauthIntegrity = 0x0001
	contextEncryption       = 0x0002
	contextCompression      = 0x0003
	contextNetname          = 0x0005
	contextTransport        = 0x0006
	contextRDMATransform    = 0x0007
	contextSigning          = 0x0008
)

// signingKeyLabel is the 3.1.1 key-derivation label. The terminating null is
// part of the label ([MS-SMB2] section 3.1.4.2).
const signingKeyLabel = "SMBSigningKey\x00"

// Hash and signing algorithm identifiers.
const (
	hashSHA512 = 0x0001

	signHMACSHA256 = 0x0000
	signAESCMAC    = 0x0001
	signAESGMAC    = 0x0002
)

// NT statuses ([MS-ERREF] section 2.3.1). Only the ones this package can
// return are named.
const (
	statusSuccess                = 0x00000000
	statusPending                = 0x00000103
	statusNoMoreFiles            = 0x80000006
	statusBufferOverflow         = 0x80000005
	statusNotImplemented         = 0xC0000002
	statusInvalidInfoClass       = 0xC0000003
	statusInfoLengthMismatch     = 0xC0000004
	statusInvalidHandle          = 0xC0000008
	statusInvalidParameter       = 0xC000000D
	statusNoSuchFile             = 0xC000000F
	statusInvalidDeviceRequest   = 0xC0000010
	statusEndOfFile              = 0xC0000011
	statusMoreProcessingRequired = 0xC0000016
	statusAccessDenied           = 0xC0000022
	statusObjectNameInvalid      = 0xC0000033
	statusObjectNameNotFound     = 0xC0000034
	statusObjectNameCollision    = 0xC0000035
	statusObjectPathNotFound     = 0xC000003A
	statusObjectPathSyntaxBad    = 0xC000003B
	statusSharingViolation       = 0xC0000043
	statusDeletePending          = 0xC0000056
	statusLockNotGranted         = 0xC0000055
	statusRangeNotLocked         = 0xC000007E
	statusDiskFull               = 0xC000007F
	statusInsufficientResources  = 0xC000009A
	statusMediaWriteProtected    = 0xC00000A2
	statusFileIsADirectory       = 0xC00000BA
	statusNotSupported           = 0xC00000BB
	statusNetworkNameDeleted     = 0xC00000C9
	statusBadNetworkName         = 0xC00000CC
	statusDirectoryNotEmpty      = 0xC0000101
	statusNotADirectory          = 0xC0000103
	statusCancelled              = 0xC0000120
	statusFileClosed             = 0xC0000128
	statusLogonFailure           = 0xC000006D
	statusUserSessionDeleted     = 0xC0000203
	statusUnsuccessful           = 0xC0000001
)

const (
	// headerSize is the fixed SMB2 header, and the smallest message.
	headerSize = 64
	// transportHeaderSize is the direct-TCP frame prefix: one zero byte and a
	// 24-bit big-endian length.
	transportHeaderSize = 4
	// maxFrameBytes is what the 24-bit length field can express.
	maxFrameBytes = (1 << 24) - 1
	// frameHeadroom covers the header, the command structures, and the
	// padding around one maximum-size read or write.
	frameHeadroom = 64 << 10

	// maxChainedMessages bounds one compound chain.
	maxChainedMessages = 64
	// maxOutstanding bounds the requests in flight on one connection.
	maxOutstanding = 64
	// maxCredits bounds the credits a client may hold at once.
	maxCredits = 512
	// maxDialects bounds the dialect list of a NEGOTIATE.
	maxDialects = 64
	// maxNegotiateContexts bounds the contexts of a 3.1.1 NEGOTIATE.
	maxNegotiateContexts = 8
	// maxSecurityBuffer bounds an authentication token.
	maxSecurityBuffer = 64 << 10
	// preauthHashSize is the SHA-512 output the 3.1.1 chain carries.
	preauthHashSize = 64
	// preauthSaltSize is the salt the server puts in its context.
	preauthSaltSize          = 32
	maxPathBytes             = 32760
	maxCreateContexts        = 16
	maxLockElements          = 64
	maxHandlesPerSession     = 4096
	maxDirectorySnapshots    = 64
	maxSessionsPerConnection = 64
	maxTreesPerSession       = 64
	maxLocksPerSession       = 65536
)

const (
	accessReadData     = 0x00000001
	accessWriteData    = 0x00000002
	accessAppendData   = 0x00000004
	accessDelete       = 0x00010000
	accessGenericAll   = 0x10000000
	accessGenericWrite = 0x40000000
	accessGenericRead  = 0x80000000

	shareRead   = 0x00000001
	shareWrite  = 0x00000002
	shareDelete = 0x00000004

	fileSupersede   = 0
	fileOpen        = 1
	fileCreate      = 2
	fileOpenIf      = 3
	fileOverwrite   = 4
	fileOverwriteIf = 5

	fileDirectoryFile    = 0x00000001
	fileWriteThrough     = 0x00000002
	fileDeleteOnClose    = 0x00001000
	fileNonDirectoryFile = 0x00000040
)
