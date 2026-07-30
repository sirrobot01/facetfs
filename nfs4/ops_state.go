package nfs4

import (
	"github.com/sirrobot01/facetfs/internal/xdr"
)

const maxClientOwnerID = 1024

func (c *compound) setClientID(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	var verifier [8]byte
	copy(verifier[:], d.OpaqueFixed(8))
	ownerID := d.Opaque(maxClientOwnerID)
	// Callback information is decoded for framing and discarded: delegations
	// are never granted, so no callback path is ever established.
	d.Uint32()   // cb_program
	d.String(16) // r_netid
	d.String(64) // r_addr
	d.Uint32()   // callback_ident
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	id, confirmVerf, st := c.s.state.setClientID(string(ownerID), verifier, principalOf(c.cred))
	if st != nfs4OK {
		e.Uint32(uint32(st))
		// NFS4ERR_CLID_INUSE carries the holder's address; none is tracked.
		e.String("tcp")
		e.String("")
		return st
	}
	e.Uint32(uint32(nfs4OK))
	e.Uint64(id)
	e.OpaqueFixed(confirmVerf[:])
	return nfs4OK
}

func (c *compound) setClientIDConfirm(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	id := d.Uint64()
	var confirmVerf [8]byte
	copy(confirmVerf[:], d.OpaqueFixed(8))
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	return status(e, c.s.state.confirmClientID(id, confirmVerf))
}

func (c *compound) renew(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	id := d.Uint64()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	return status(e, c.s.state.renew(id))
}
