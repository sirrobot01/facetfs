package nfs4

import (
	"errors"
	"net"
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

	// callbackTimeout bounds the dial and the CB_NULL round trip. A callback
	// path is commonly unreachable (the client is behind a firewall or address
	// translation), so the probe runs off every request path and just gives up.
	callbackTimeout = 5 * time.Second

	// maxCallbackReplyBytes caps a reply record from the client. A CB_NULL
	// reply is one RPC header.
	maxCallbackReplyBytes = 512

	cbNullXID = 1
)

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
	d := xdr.NewDecoder(reply)
	xid := d.Uint32()
	mtype := d.Uint32()
	stat := d.Uint32()
	d.Uint32()             // verifier flavor
	d.Opaque(maxCredBytes) // verifier body
	accept := d.Uint32()
	if d.Err() != nil || xid != cbNullXID || mtype != msgReply ||
		stat != replyAccepted || accept != acceptSuccess {
		return errors.New("nfs4: callback ping refused")
	}
	return nil
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
