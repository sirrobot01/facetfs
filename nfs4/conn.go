package nfs4

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

const authBadVerf = 3

var errFraming = errors.New("nfs4: malformed record or RPC header")

type authSysCred struct {
	uid, gid uint32
	machine  string
}

// readRecord reassembles one RPC record (RFC 5531 §11). The record is capped
// at maxTotal, which the server derives from its write limit so that a WRITE
// of the advertised maxwrite always fits; a peer exceeding it loses the
// connection, because a reply cannot be correlated to an unread request.
func readRecord(r io.Reader, maxTotal int) ([]byte, error) {
	var record []byte
	for {
		var marker [4]byte
		if _, err := io.ReadFull(r, marker[:]); err != nil {
			if len(record) > 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		m := binary.BigEndian.Uint32(marker[:])
		last := m&(1<<31) != 0
		size := int(m & (1<<31 - 1))
		if len(record)+size > maxTotal {
			return nil, errFraming
		}
		record = append(record, make([]byte, size)...)
		if _, err := io.ReadFull(r, record[len(record)-size:]); err != nil {
			return nil, io.ErrUnexpectedEOF
		}
		if last {
			return record, nil
		}
	}
}

func writeRecord(w io.Writer, body []byte) error {
	var marker [4]byte
	binary.BigEndian.PutUint32(marker[:], uint32(len(body))|1<<31)
	if _, err := w.Write(marker[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) error {
	defer c.Close()

	watchdog := make(chan struct{})
	defer close(watchdog)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-watchdog:
		}
	}()

	// One reader, per-request workers behind a semaphore, one writer.
	// Replies may interleave in any order; the xid correlates them.
	replies := make(chan []byte, maxInflight)
	writerDone := make(chan struct{})
	var writeErr error
	go func() {
		defer close(writerDone)
		for reply := range replies {
			if writeErr == nil {
				if writeErr = writeRecord(c, reply); writeErr != nil {
					c.Close()
				}
			}
		}
	}()

	sem := make(chan struct{}, maxInflight)
	var workers sync.WaitGroup
	var readErr error
	for {
		record, err := readRecord(c, s.requestCap())
		if err != nil {
			readErr = err
			break
		}
		sem <- struct{}{}
		workers.Go(func() {
			defer func() { <-sem }()
			if reply, ok := s.handleRecord(ctx, record); ok {
				replies <- reply
			} else {
				// Too malformed to answer; the reader unblocks with an error.
				c.Close()
			}
		})
	}
	workers.Wait()
	close(replies)
	<-writerDone

	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(readErr, io.EOF):
		return nil
	case writeErr != nil:
		return fmt.Errorf("nfs4: write: %w", writeErr)
	default:
		return readErr
	}
}

// handleRecord parses one RPC call and returns the encoded reply. ok=false
// tears down the connection: the header was too malformed to answer.
func (s *Server) handleRecord(ctx context.Context, record []byte) (reply []byte, ok bool) {
	d := xdr.NewDecoder(record)
	xid := d.Uint32()
	mtype := d.Uint32()
	rpcvers := d.Uint32()
	if d.Err() != nil || mtype != msgCall {
		return nil, false
	}
	if rpcvers != rpcVersion {
		var e xdr.Encoder
		e.Uint32(xid)
		e.Uint32(msgReply)
		e.Uint32(replyDenied)
		e.Uint32(rejectRPCMismatch)
		e.Uint32(rpcVersion)
		e.Uint32(rpcVersion)
		return e.Bytes(), true
	}
	prog := d.Uint32()
	vers := d.Uint32()
	proc := d.Uint32()

	credFlavor := d.Uint32()
	credBody := d.Opaque(maxCredBytes)
	verfFlavor := d.Uint32()
	d.Opaque(maxCredBytes)
	if d.Err() != nil {
		return nil, false
	}
	if verfFlavor != authNone {
		return authError(xid, authBadVerf), true
	}
	var cred *authSysCred
	switch credFlavor {
	case authNone:
	case authSys:
		var err error
		if cred, err = parseAuthSys(credBody); err != nil {
			return authError(xid, authBadCred), true
		}
	default:
		return authError(xid, authBadCred), true
	}

	switch {
	case prog != nfsProgram:
		return accepted(xid, acceptProgUnavail, nil), true
	case vers != nfsVersion:
		var e xdr.Encoder
		e.Uint32(nfsVersion)
		e.Uint32(nfsVersion)
		return accepted(xid, acceptProgMismatch, e.Bytes()), true
	}
	switch proc {
	case procNull:
		return accepted(xid, acceptSuccess, nil), true
	case procCompound:
		result, ok := s.compound(ctx, cred, d)
		if !ok {
			return accepted(xid, acceptGarbageArgs, nil), true
		}
		return accepted(xid, acceptSuccess, result), true
	default:
		return accepted(xid, acceptProcUnavail, nil), true
	}
}

func parseAuthSys(body []byte) (*authSysCred, error) {
	d := xdr.NewDecoder(body)
	d.Uint32() // stamp
	cred := &authSysCred{machine: d.String(maxNameBytes)}
	cred.uid = d.Uint32()
	cred.gid = d.Uint32()
	n := d.Uint32()
	if n > maxAuthSysGids {
		return nil, xdr.ErrBound
	}
	for range n {
		d.Uint32()
	}
	if d.Err() != nil {
		return nil, d.Err()
	}
	return cred, nil
}

func accepted(xid uint32, stat uint32, body []byte) []byte {
	var e xdr.Encoder
	e.Uint32(xid)
	e.Uint32(msgReply)
	e.Uint32(replyAccepted)
	e.Uint32(authNone)
	e.Uint32(0)
	e.Uint32(stat)
	e.OpaqueFixed(body)
	return e.Bytes()
}

func authError(xid uint32, stat uint32) []byte {
	var e xdr.Encoder
	e.Uint32(xid)
	e.Uint32(msgReply)
	e.Uint32(replyDenied)
	e.Uint32(rejectAuthError)
	e.Uint32(stat)
	return e.Bytes()
}
