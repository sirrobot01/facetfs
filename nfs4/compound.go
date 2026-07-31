package nfs4

import (
	"context"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

// compound carries one COMPOUND's execution state. The filehandle slots hold
// unsealed cleaned paths; "" is not a usable sentinel because "/" is valid,
// hence the explicit has flags.
type compound struct {
	s        *Server
	ctx      context.Context
	cred     *authSysCred
	fh       string
	hasFH    bool
	saved    string
	hasSaved bool
}

// opFunc decodes its arguments, encodes its own status-first result body, and
// returns the status for control flow. Ops encode status themselves because
// several (SETATTR, SETCLIENTID, LOCK) carry non-empty error bodies.
type opFunc func(*compound, *xdr.Decoder, *xdr.Encoder) nfsStat

// opTable is indexed by op number; nil entries answer NFS4ERR_NOTSUPP.
var opTable = [40]opFunc{
	opAccess:             (*compound).access,
	opClose:              (*compound).close,
	opCommit:             (*compound).commit,
	opCreate:             (*compound).create,
	opGetAttr:            (*compound).getAttr,
	opGetFH:              (*compound).getFH,
	opLink:               (*compound).link,
	opLock:               (*compound).lock,
	opLockT:              (*compound).lockT,
	opLockU:              (*compound).lockU,
	opLookup:             (*compound).lookup,
	opLookupP:            (*compound).lookupP,
	opNVerify:            (*compound).nVerify,
	opOpen:               (*compound).open,
	opOpenConfirm:        (*compound).openConfirm,
	opOpenDowngrade:      (*compound).openDowngrade,
	opPutFH:              (*compound).putFH,
	opPutPubFH:           (*compound).putRootFH,
	opPutRootFH:          (*compound).putRootFH,
	opRead:               (*compound).read,
	opReadDir:            (*compound).readDir,
	opReadLink:           (*compound).readLink,
	opRemove:             (*compound).remove,
	opRename:             (*compound).rename,
	opRenew:              (*compound).renew,
	opRestoreFH:          (*compound).restoreFH,
	opSaveFH:             (*compound).saveFH,
	opSecInfo:            (*compound).secInfo,
	opSetAttr:            (*compound).setAttr,
	opSetClientID:        (*compound).setClientID,
	opSetClientIDConfirm: (*compound).setClientIDConfirm,
	opVerify:             (*compound).verify,
	opWrite:              (*compound).write,
	opReleaseLockOwner:   (*compound).releaseLockOwner,
}

// compound executes one COMPOUND call (RFC 7530 §15.2) and appends the reply
// to e. It reports false when the top-level arguments did not decode, which
// the RPC layer answers with GARBAGE_ARGS.
func (s *Server) compound(ctx context.Context, cred *authSysCred, d *xdr.Decoder, e *xdr.Encoder) bool {
	s.state.sweepDue()
	tag := d.Opaque(maxTagBytes)
	minor := d.Uint32()
	numOps := d.Uint32()
	if d.Err() != nil {
		return false
	}

	// The status and the operation count are only known once every operation
	// has run, so they are reserved now and filled in at the end.
	statusAt := e.Len()
	e.Uint32(0)
	e.Opaque(tag)
	countAt := e.Len()
	e.Uint32(0)
	resultsFrom := e.Len()

	status := nfs4OK
	count := uint32(0)

	switch {
	case minor != 0:
		status = nfs4ErrMinorVersMismatch
	case numOps > maxCompoundOps:
		status = nfs4ErrResource
	default:
		c := &compound{s: s, ctx: ctx, cred: cred}
		for ; count < numOps; count++ {
			opnum := d.Uint32()
			if d.Err() != nil {
				// Garbled mid-stream: answer with the ops already run.
				break
			}
			mark := e.Len()
			var op opFunc
			if opnum >= opAccess && opnum < uint32(len(opTable)) {
				op = opTable[opnum]
			}
			if op == nil {
				if opnum >= opAccess && opnum < uint32(len(opTable)) {
					e.Uint32(opnum)
					e.Uint32(uint32(nfs4ErrNotSupp))
					status = nfs4ErrNotSupp
				} else {
					e.Uint32(opIllegal)
					e.Uint32(uint32(nfs4ErrOpIllegal))
					status = nfs4ErrOpIllegal
				}
				count++
				break
			}
			e.Uint32(opnum)
			status = op(c, d, e)
			if e.Len()-resultsFrom > s.responseCap() {
				e.Truncate(mark)
				e.Uint32(opnum)
				e.Uint32(uint32(nfs4ErrResource))
				status = nfs4ErrResource
			}
			if status != nfs4OK {
				count++
				break
			}
		}
	}

	e.PatchUint32(statusAt, uint32(status))
	e.PatchUint32(countAt, count)
	return true
}
