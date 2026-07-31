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

// compound executes one COMPOUND call (RFC 7530 §15.2). ok=false means the
// top-level arguments did not decode: the RPC layer answers GARBAGE_ARGS.
func (s *Server) compound(ctx context.Context, cred *authSysCred, d *xdr.Decoder) ([]byte, bool) {
	s.state.sweepExpired()
	tag := d.Opaque(maxTagBytes)
	minor := d.Uint32()
	numOps := d.Uint32()
	if d.Err() != nil {
		return nil, false
	}

	var results xdr.Encoder
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
			mark := results.Len()
			var op opFunc
			if opnum >= opAccess && opnum < uint32(len(opTable)) {
				op = opTable[opnum]
			}
			if op == nil {
				if opnum >= opAccess && opnum < uint32(len(opTable)) {
					results.Uint32(opnum)
					results.Uint32(uint32(nfs4ErrNotSupp))
					status = nfs4ErrNotSupp
				} else {
					results.Uint32(opIllegal)
					results.Uint32(uint32(nfs4ErrOpIllegal))
					status = nfs4ErrOpIllegal
				}
				count++
				break
			}
			results.Uint32(opnum)
			status = op(c, d, &results)
			if results.Len() > s.responseCap() {
				results.Truncate(mark)
				results.Uint32(opnum)
				results.Uint32(uint32(nfs4ErrResource))
				status = nfs4ErrResource
			}
			if status != nfs4OK {
				count++
				break
			}
		}
	}

	var e xdr.Encoder
	e.Uint32(uint32(status))
	e.Opaque(tag)
	e.Uint32(count)
	e.OpaqueFixed(results.Bytes())
	return e.Bytes(), true
}
