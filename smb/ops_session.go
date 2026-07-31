package smb

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"strings"
)

func advancePreauth(seed [preauthHashSize]byte, wire []byte) [preauthHashSize]byte {
	b := make([]byte, 0, preauthHashSize+len(wire))
	b = append(b, seed[:]...)
	b = append(b, wire...)
	return sha512.Sum512(b)
}

func (conn *connection) sessionSetup(ctx context.Context, m *message) ([]byte, uint32) {
	if len(m.body) < 24 || binary.LittleEndian.Uint16(m.body) != 25 {
		return nil, statusInvalidParameter
	}
	off := uint32(binary.LittleEndian.Uint16(m.body[12:]))
	n := uint32(binary.LittleEndian.Uint16(m.body[14:]))
	blob, ok := m.slice(off, n, maxSecurityBuffer)
	if !ok || len(blob) == 0 {
		return nil, statusInvalidParameter
	}
	token, ok := ntlmToken(blob)
	if !ok {
		return nil, statusLogonFailure
	}
	// The response mirrors the client's framing. The Linux kernel client
	// sends NTLM without a SPNEGO wrapper and rejects a wrapped challenge;
	// Windows and macOS send SPNEGO and expect it back.
	raw := bytes.HasPrefix(blob, ntlmSignature)
	typ, ok := ntlmType(token)
	if !ok {
		return nil, statusLogonFailure
	}
	switch typ {
	case 1:
		if m.hdr.sessionID != 0 {
			return nil, statusInvalidParameter
		}
		sess, ok := conn.s.state.newSession(conn)
		if !ok {
			return nil, statusInsufficientResources
		}
		challenge, ok := freshChallenge()
		if !ok {
			conn.s.state.closeSession(sess)
			return nil, statusInsufficientResources
		}
		conn.mu.Lock()
		sess.mu.Lock()
		sess.preauth = conn.preauth
		// Session.SigningRequired: the server demands signing, or the client
		// does ([MS-SMB2] section 3.3.5.5.3). A client that only reports it
		// can sign is not held to signing every message.
		sess.sign = conn.s.RequireSigning || m.body[3]&signingRequired != 0
		sess.mu.Unlock()
		conn.mu.Unlock()
		if conn.s.RequireSigning && m.body[3]&(signingEnabled|signingRequired) == 0 {
			conn.s.state.closeSession(sess)
			return nil, statusAccessDenied
		}
		sess.mu.Lock()
		sess.preauth = advancePreauth(sess.preauth, m.raw)
		sess.challenge = challenge
		challengeToken, flags := ntlmChallenge(conn.s.serverName(), challenge)
		sess.ntlmFlags = flags
		sess.mu.Unlock()
		m.hdr.sessionID = sess.id
		if raw {
			return sessionSetupResponse(challengeToken), statusMoreProcessingRequired
		}
		return sessionSetupResponse(spnegoChallenge(challengeToken)), statusMoreProcessingRequired
	case 3:
		sess := conn.s.state.session(m.hdr.sessionID, conn)
		if sess == nil {
			return nil, statusUserSessionDeleted
		}
		sess.mu.Lock()
		if sess.authenticated || sess.authenticating {
			sess.mu.Unlock()
			return nil, statusUserSessionDeleted
		}
		sess.authenticating = true
		sess.preauth = advancePreauth(sess.preauth, m.raw)
		challenge := sess.challenge
		preauth := sess.preauth
		sess.mu.Unlock()
		result, ok := authenticateNTLM(ctx, conn.s.Authenticator, token, challenge)
		if !ok {
			conn.s.state.closeSession(sess)
			return nil, statusLogonFailure
		}
		sess.mu.Lock()
		sess.user = result.domain + "\\" + result.user
		if conn.dialect == dialect311 {
			sess.signingKey = smbKDF(result.key, signingKeyLabel, preauth[:])
		} else {
			sess.signingKey = append([]byte(nil), result.key...)
		}
		sess.authenticated = true
		sess.authenticating = false
		sess.mu.Unlock()
		if raw {
			return sessionSetupResponse(nil), statusSuccess
		}
		return sessionSetupResponse(spnegoComplete()), statusSuccess
	default:
		return nil, statusLogonFailure
	}
}

func sessionSetupResponse(token []byte) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b, 9)
	if len(token) != 0 {
		binary.LittleEndian.PutUint16(b[4:], headerSize+8)
		binary.LittleEndian.PutUint16(b[6:], uint16(len(token)))
		b = append(b, token...)
	}
	return b
}

func (conn *connection) treeConnect(m *message) ([]byte, uint32) {
	sess := conn.authSession(m)
	if sess == nil {
		return nil, statusUserSessionDeleted
	}
	if len(m.body) < 8 || binary.LittleEndian.Uint16(m.body) != 9 {
		return nil, statusInvalidParameter
	}
	off := uint32(binary.LittleEndian.Uint16(m.body[4:]))
	n := uint32(binary.LittleEndian.Uint16(m.body[6:]))
	wire, ok := m.slice(off, n, maxPathBytes)
	if !ok {
		return nil, statusInvalidParameter
	}
	unc, ok := decodeUTF16(wire)
	if !ok {
		return nil, statusBadNetworkName
	}
	parts := strings.Split(strings.TrimPrefix(unc, "\\\\"), "\\")
	if len(parts) != 2 || parts[0] == "" || !strings.EqualFold(parts[1], conn.s.shareName()) || strings.EqualFold(parts[1], "IPC$") {
		return nil, statusBadNetworkName
	}
	conn.s.state.mu.Lock()
	if len(sess.trees) >= maxTreesPerSession {
		conn.s.state.mu.Unlock()
		return nil, statusInsufficientResources
	}
	sess.nextTree++
	if sess.nextTree == 0 {
		sess.nextTree++
	}
	t := &tree{id: sess.nextTree}
	sess.trees[t.id] = t
	conn.s.state.mu.Unlock()
	m.hdr.treeID = t.id
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b, 16)
	b[2] = 1 // SMB2_SHARE_TYPE_DISK
	binary.LittleEndian.PutUint32(b[12:], 0x001f01ff)
	return b, statusSuccess
}

func (conn *connection) treeDisconnect(m *message) ([]byte, uint32) {
	sess := conn.authSession(m)
	if sess == nil {
		return nil, statusUserSessionDeleted
	}
	if len(m.body) < 4 || binary.LittleEndian.Uint16(m.body) != 4 {
		return nil, statusInvalidParameter
	}
	conn.s.state.mu.Lock()
	if sess.trees[m.hdr.treeID] == nil {
		conn.s.state.mu.Unlock()
		return nil, statusInvalidParameter
	}
	delete(sess.trees, m.hdr.treeID)
	var handles []*openHandle
	for _, h := range sess.handles {
		if h.treeID == m.hdr.treeID {
			handles = append(handles, h)
		}
	}
	conn.s.state.mu.Unlock()
	for _, h := range handles {
		conn.closeOpen(h)
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, 4)
	return b, statusSuccess
}

func (conn *connection) logoff(m *message) ([]byte, uint32) {
	sess := conn.authSession(m)
	if sess == nil {
		return nil, statusUserSessionDeleted
	}
	if len(m.body) < 4 || binary.LittleEndian.Uint16(m.body) != 4 {
		return nil, statusInvalidParameter
	}
	// The connection closes the session after the response has been signed.
	m.closeSession = sess
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, 4)
	return b, statusSuccess
}

func (conn *connection) authSession(m *message) *session {
	s := conn.s.state.session(m.hdr.sessionID, conn)
	if s == nil {
		return nil
	}
	s.mu.Lock()
	authenticated := s.authenticated
	s.mu.Unlock()
	if !authenticated {
		return nil
	}
	return s
}
