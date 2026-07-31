package nfs4

import (
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

// The callback protocol (RFC 7530 §16.2) reverses the roles: the server is
// the RPC client. The program number is the client's cb_program from
// SETCLIENTID; the version is fixed.
const (
	callbackVersion = 1
	cbProcNull      = 0
	cbProcCompound  = 1
	opCBRecall      = 4

	// callbackTimeout bounds the dial and one callback round trip. A callback
	// path is commonly unreachable (the client is behind a firewall or address
	// translation), so callback calls run off every request path and give up.
	callbackTimeout = 5 * time.Second

	// maxCallbackReplyBytes caps a reply record from the client. CB_NULL and
	// CB_RECALL replies are one RPC header and a few words.
	maxCallbackReplyBytes = 512

	cbNullXID   = 1
	cbRecallXID = 2
)

// recallTimeout is how long a recalled client has to send DELEGRETURN before
// the delegation is revoked. It matches the default lease: a client that
// cannot answer a recall within one is treated like a client that lost it.
// It is a variable only so tests can shorten it.
var recallTimeout = 90 * time.Second

// callbackPath is the client's callback service as announced in SETCLIENTID.
// An empty addr means the announcement was absent or unusable; the client is
// served normally and never receives a delegation.
type callbackPath struct {
	program uint32
	ident   uint32 // echoed in CB_COMPOUND (RFC 7530 §15.2)
	addr    string // dial address, or "" when unusable
}

var errUniversalAddr = errors.New("nfs4: malformed universal address")

// parseUniversalAddr converts an ONC RPC universal address into a dial
// address. The form is the endpoint address followed by two port octets, all
// dot separated: "a.b.c.d.p1.p2" on netid "tcp", the IPv6 text form in place
// of "a.b.c.d" on "tcp6". The port is p1*256 + p2.
func parseUniversalAddr(netid, uaddr string) (string, error) {
	if netid != "tcp" && netid != "tcp6" {
		return "", errUniversalAddr
	}
	rest, p2, err := splitPortOctet(uaddr)
	if err != nil {
		return "", err
	}
	host, p1, err := splitPortOctet(rest)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	if ip == nil || (netid == "tcp") != (ip.To4() != nil) {
		return "", errUniversalAddr
	}
	port := p1<<8 + p2
	if port == 0 || ip.IsUnspecified() {
		return "", errUniversalAddr
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// splitPortOctet takes one decimal octet off the end of a dot-separated
// address.
func splitPortOctet(s string) (rest string, octet int, err error) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", 0, errUniversalAddr
	}
	n, err := strconv.ParseUint(s[i+1:], 10, 8)
	if err != nil {
		return "", 0, errUniversalAddr
	}
	return s[:i], int(n), nil
}

// pingCallback dials the callback path and calls CB_NULL. A nil return means
// the path answered.
func pingCallback(cb callbackPath) error {
	c, err := net.DialTimeout("tcp", cb.addr, callbackTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(callbackTimeout))

	e := xdr.NewEncoder(nil)
	e.Uint32(cbNullXID)
	e.Uint32(msgCall)
	e.Uint32(rpcVersion)
	e.Uint32(cb.program)
	e.Uint32(callbackVersion)
	e.Uint32(cbProcNull)
	e.Uint32(authNone)
	e.Uint32(0)
	e.Uint32(authNone)
	e.Uint32(0)
	if err := writeRecord(c, e.Bytes()); err != nil {
		return err
	}

	reply, err := readRecord(c, maxCallbackReplyBytes)
	if err != nil {
		return err
	}
	return parseAcceptedReply(reply, cbNullXID)
}

// parseAcceptedReply checks an RPC reply record for an accepted, successful
// call. Callback replies arrive from outside, so the decode is bounded like
// every other.
func parseAcceptedReply(record []byte, xid uint32) error {
	d := xdr.NewDecoder(record)
	gotXID := d.Uint32()
	mtype := d.Uint32()
	stat := d.Uint32()
	d.Uint32()             // verifier flavor
	d.Opaque(maxCredBytes) // verifier body
	accept := d.Uint32()
	if d.Err() != nil || gotXID != xid || mtype != msgReply ||
		stat != replyAccepted || accept != acceptSuccess {
		return errors.New("nfs4: callback call refused")
	}
	return nil
}

// sendCBRecall dials the client's callback path and issues CB_RECALL
// (RFC 7530 §15.2.3). The reply is advisory: a client that answers returns
// the delegation with DELEGRETURN, and one that does not loses it when the
// recall times out.
func sendCBRecall(cb callbackPath, seq uint32, other [12]byte, fh []byte) error {
	c, err := net.DialTimeout("tcp", cb.addr, callbackTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(callbackTimeout))

	e := xdr.NewEncoder(nil)
	e.Uint32(cbRecallXID)
	e.Uint32(msgCall)
	e.Uint32(rpcVersion)
	e.Uint32(cb.program)
	e.Uint32(callbackVersion)
	e.Uint32(cbProcCompound)
	e.Uint32(authNone)
	e.Uint32(0)
	e.Uint32(authNone)
	e.Uint32(0)
	e.Opaque(nil) // tag
	e.Uint32(0)   // minorversion
	e.Uint32(cb.ident)
	e.Uint32(1) // one operation
	e.Uint32(opCBRecall)
	e.Uint32(seq)
	e.OpaqueFixed(other[:])
	e.Bool(false) // the file is not being truncated away
	e.Opaque(fh)
	if err := writeRecord(c, e.Bytes()); err != nil {
		return err
	}
	reply, err := readRecord(c, maxCallbackReplyBytes)
	if err != nil {
		return err
	}
	return parseAcceptedReply(reply, cbRecallXID)
}

// recallDelegations clears the way for an operation that would make path's
// delegations false. It revokes what a recall timeout has already forfeited,
// starts a recall for what is still live, and reports NFS4ERR_DELAY for the
// caller to answer while the holders return them. Recalls are sent from
// their own goroutines, outside every state mutex. Delegations held by
// except are left alone: a client's own writes do not make its cache stale.
func (s *Server) recallDelegations(p string, except *client) nfsStat {
	type recallJob struct {
		cb    callbackPath
		seq   uint32
		other [12]byte
		path  string
	}
	st := s.state
	now := st.now()
	var jobs []recallJob
	blocked := false
	st.mu.Lock()
	// Revocation edits the slice, so iterate a copy.
	for _, dl := range slices.Clone(st.delegsByPath[p]) {
		if dl.client == except {
			continue
		}
		if dl.recalling && !now.Before(dl.recallAt.Add(st.recallWait)) {
			st.revokeDelegationLocked(dl, now)
			continue
		}
		blocked = true
		if !dl.recalling {
			dl.recalling = true
			dl.recallAt = now
			jobs = append(jobs, recallJob{cb: dl.client.cb, seq: dl.seq, other: dl.other, path: dl.path})
		}
	}
	st.mu.Unlock()
	for _, job := range jobs {
		go sendCBRecall(job.cb, job.seq, job.other, s.fh.seal(job.path))
	}
	if blocked {
		return nfs4ErrDelay
	}
	return nfs4OK
}

// probeCallback records whether the client's callback path answers CB_NULL.
// It runs in its own goroutine: a firewalled path costs a request nothing,
// and no state mutex is ever held across the dial. A path that does not
// answer is not an error — the client is served, it just gets no delegations.
func (s *Server) probeCallback(c *client) {
	if pingCallback(c.cb) != nil {
		return
	}
	st := s.state
	st.mu.Lock()
	if st.confirmed[c.id] == c {
		c.cbUp = true
	}
	st.mu.Unlock()
}
