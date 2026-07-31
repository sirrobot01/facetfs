package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

var errFraming = errors.New("smb: malformed frame or header")

// readFrame reads one direct-TCP frame: a zero byte, a 24-bit big-endian
// length, then the message ([MS-SMB2] section 2.1). A frame above the limit
// ends the connection, because a reply cannot be correlated to a message the
// server did not read.
func readFrame(r io.Reader, maxTotal int) ([]byte, error) {
	var prefix [transportHeaderSize]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	if prefix[0] != 0 {
		return nil, errFraming
	}
	size := int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3])
	// The smallest message the server answers is an SMB1 multi-protocol
	// NEGOTIATE, which is shorter than an SMB2 header. A short SMB2 message
	// fails its header decode instead.
	if size < smb1MinNegotiate || size > maxTotal {
		return nil, errFraming
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return frame, nil
}

func writeFrame(w io.Writer, body []byte) error {
	if len(body) > maxFrameBytes {
		return errFraming
	}
	var prefix [transportHeaderSize]byte
	prefix[1] = byte(len(body) >> 16)
	prefix[2] = byte(len(body) >> 8)
	prefix[3] = byte(len(body))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// connection is one client connection. What a negotiation settles lives here,
// because it is per connection and not per session.
type connection struct {
	s *Server
	c net.Conn

	mu sync.Mutex
	// negotiated records that a NEGOTIATE was attempted, which claims the one
	// negotiation a connection gets. dialect records that one succeeded, and
	// is what lets any other command run. smb1 records that the SMB1
	// multi-protocol step already ran, which is the one such step a
	// connection gets.
	negotiated         bool
	smb1               bool
	dialect            uint16
	signAlg            uint16
	clientSigning      bool
	clientSecurityMode uint16
	clientCapabilities uint32
	clientGUID         [16]byte
	// preauth is the running SHA-512 that binds a 3.1.1 session key to the
	// exact negotiation. Section 7.1 of the component design.
	preauth [preauthHashSize]byte
	credits int
	window  messageWindow
}

// messageWindow refuses a message id the client has already used, and one too
// far ahead of the ids still in flight. Without it a client could replay a
// write it already sent.
type messageWindow struct {
	base uint64
	used [maxCredits * 2]bool
}

func (w *messageWindow) take(id uint64) bool {
	span := uint64(len(w.used))
	if id < w.base || id >= w.base+span {
		return false
	}
	slot := int(id % span)
	if w.used[slot] {
		return false
	}
	w.used[slot] = true
	// Forget the ids below the lowest one still outstanding. A replay of one
	// of those is refused by the base comparison instead.
	for w.used[int(w.base%span)] {
		w.used[int(w.base%span)] = false
		w.base++
	}
	return true
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

	// One credit is granted implicitly so the client may send its first
	// request. Every credit after that is granted in a response.
	conn := &connection{s: s, c: c, credits: 1}
	defer s.state.closeConnection(conn)

	// One reader, per-frame workers behind a semaphore, one writer.
	type outbound struct {
		frame      []byte
		closeAfter bool
	}
	replies := make(chan outbound, maxOutstanding)
	writerDone := make(chan struct{})
	var writeErr error
	go func() {
		defer close(writerDone)
		for reply := range replies {
			if writeErr == nil {
				if writeErr = writeFrame(c, reply.frame); writeErr != nil {
					c.Close()
				}
			}
			if reply.closeAfter {
				c.Close()
			}
		}
	}()

	sem := make(chan struct{}, maxOutstanding)
	var workers sync.WaitGroup
	var readErr error
	for {
		frame, err := readFrame(c, s.frameCap())
		if err != nil {
			readErr = err
			break
		}
		if [4]byte(frame[0:4]) == smb1ProtocolID {
			// A multi-protocol negotiate is answered in SMB2 so the client
			// negotiates again in SMB2. Any other SMB1 message is refused.
			reply, stepUp := conn.smb1Negotiate(frame)
			replies <- outbound{frame: reply, closeAfter: !stepUp}
			if !stepUp {
				readErr = errors.New("smb: client offered SMB1")
				break
			}
			continue
		}
		sem <- struct{}{}
		workers.Go(func() {
			defer func() { <-sem }()
			reply, ok, closeAfter := conn.handleFrame(ctx, frame)
			if !ok {
				// Too malformed to answer; the reader unblocks with an error.
				c.Close()
				return
			}
			if reply != nil {
				replies <- outbound{frame: reply, closeAfter: closeAfter}
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
		return fmt.Errorf("smb: write: %w", writeErr)
	default:
		return readErr
	}
}

// handleFrame runs every message of one frame and returns the reply frame. It
// reports false when the frame was too malformed to answer, which tears the
// connection down.
//
// A related message inherits the session, tree, and all-ones file-id reference
// of the message before it ([MS-SMB2] section 3.3.5.2.7).
func (conn *connection) handleFrame(ctx context.Context, frame []byte) ([]byte, bool, bool) {
	var reply []byte
	var sessionID uint64
	var treeID uint32
	var relatedFileID *[16]byte
	type answered struct {
		m     *message
		start int
	}
	var answers []answered
	var cleanup []*session
	// A failed message poisons the related messages after it: each depends on
	// the one before it, so they fail with its status. An unrelated message
	// starts a new group and runs on its own ([MS-SMB2] section 3.3.5.2.7).
	// A bad signature poisons the whole frame, and the connection closes.
	var relatedFailed, sigFailed bool
	var relatedStatus uint32
	closeAfter := false
	// lastHeader is where the previous response header starts, so that this
	// one can be chained onto it. Negative means there is none yet.
	lastHeader := -1
	offset := 0

	for count := 0; ; count++ {
		if count >= maxChainedMessages {
			return nil, false, false
		}
		rest := frame[offset:]
		hdr, ok := decodeHeader(rest)
		if !ok {
			return nil, false, false
		}
		// A message ends at the next command, or at the end of the frame.
		end := len(rest)
		if hdr.nextCommand != 0 {
			next := int(hdr.nextCommand)
			if next < headerSize || next%8 != 0 || next > len(rest) {
				return nil, false, false
			}
			end = next
		}
		m := &message{hdr: hdr, raw: rest[:end], body: rest[headerSize:end]}

		if !conn.admit(m) {
			return nil, false, false
		}
		if hdr.flags&flagRelatedOps != 0 {
			if count == 0 {
				return nil, false, false
			}
			m.hdr.sessionID, m.hdr.treeID = sessionID, treeID
			m.relatedFileID = relatedFileID
		} else {
			sessionID, treeID = hdr.sessionID, hdr.treeID
			relatedFileID = nil
			relatedFailed = false
		}

		sess := conn.s.state.session(m.hdr.sessionID, conn)
		var authenticated, shouldSign bool
		var signingKey []byte
		if sess != nil {
			sess.mu.Lock()
			authenticated, shouldSign = sess.authenticated, sess.sign
			signingKey = append([]byte(nil), sess.signingKey...)
			sess.mu.Unlock()
		}
		var body []byte
		var status uint32
		switch {
		case sigFailed:
			status = statusAccessDenied
		case authenticated && shouldSign && !verifyMessage(signingKey, conn.signAlg, m.raw):
			sigFailed = true
			closeAfter = true
			status = statusAccessDenied
		case relatedFailed:
			status = relatedStatus
		default:
			body, status = conn.dispatch(ctx, m)
			if status != statusSuccess && status != statusMoreProcessingRequired {
				relatedFailed, relatedStatus = true, status
			}
		}
		if m.resultFileID != nil {
			id := *m.resultFileID
			relatedFileID = &id
		}
		// CANCEL is the one command that carries no response.
		if hdr.command != cmdCancel {
			var start int
			reply, start = conn.appendResponse(reply, lastHeader, m, body, status)
			lastHeader = start
			answers = append(answers, answered{m: m, start: start})
		}
		if m.closeSession != nil {
			cleanup = append(cleanup, m.closeSession)
		}
		if hdr.nextCommand == 0 {
			break
		}
		offset += end
	}
	if len(reply) == 0 {
		return nil, true, closeAfter
	}
	// Each response of a signing session is signed on its own, with the key
	// of the session it answers; the messages of one chain can belong to
	// different sessions.
	for i, a := range answers {
		end := len(reply)
		if i+1 < len(answers) {
			end = answers[i+1].start
		}
		s := conn.s.state.session(a.m.hdr.sessionID, conn)
		if s == nil {
			continue
		}
		s.mu.Lock()
		sign := s.authenticated && s.sign
		key := append([]byte(nil), s.signingKey...)
		s.mu.Unlock()
		if sign && !signMessage(key, conn.signAlg, reply[a.start:end]) {
			return nil, false, false
		}
	}
	for i, a := range answers {
		end := len(reply)
		if i+1 < len(answers) {
			end = answers[i+1].start
		}
		wire := reply[a.start:end]
		switch a.m.hdr.command {
		case cmdNegotiate:
			if conn.dialect == dialect311 {
				conn.mu.Lock()
				conn.preauth = advancePreauth(conn.preauth, a.m.raw)
				conn.preauth = advancePreauth(conn.preauth, wire)
				conn.mu.Unlock()
			}
		case cmdSessionSetup:
			if s := conn.s.state.session(a.m.hdr.sessionID, conn); s != nil {
				s.mu.Lock()
				s.preauth = advancePreauth(s.preauth, wire)
				s.mu.Unlock()
			}
		}
	}
	for _, s := range cleanup {
		conn.s.state.closeSession(s)
	}
	return reply, true, closeAfter
}

// admit applies the credit and message-id rules to one message. It reports
// false when the client broke them, which ends the connection.
func (conn *connection) admit(m *message) bool {
	// A cancel is not credited and carries the id of the request it cancels,
	// so neither rule applies to it.
	if m.hdr.command == cmdCancel {
		return true
	}
	charge := int(m.hdr.creditCharge)
	if charge == 0 {
		charge = 1
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.window.take(m.hdr.messageID) {
		return false
	}
	if charge > conn.credits {
		return false
	}
	conn.credits -= charge
	return true
}

// grant returns the credits to put in a response. The server must never leave
// a client with none, or the client stalls forever.
func (conn *connection) grant(request uint16) uint16 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	want := max(int(request), 1)
	room := maxCredits - conn.credits
	if room <= 0 {
		return 0
	}
	if want > room {
		want = room
	}
	conn.credits += want
	return uint16(want)
}

// appendResponse chains one response onto the reply frame and reports where
// its header starts, so that a following response can point back at it.
func (conn *connection) appendResponse(reply []byte, lastHeader int, m *message, body []byte, status uint32) ([]byte, int) {
	if body == nil {
		body = errorResponse()
	}
	if lastHeader >= 0 {
		// The previous response now has a successor: pad it to the 8-byte
		// boundary and record the distance to this one.
		for len(reply)%8 != 0 {
			reply = append(reply, 0)
		}
		binary.LittleEndian.PutUint32(reply[lastHeader+20:], uint32(len(reply)-lastHeader))
	}
	start := len(reply)
	h := header{
		status:    status,
		command:   m.hdr.command,
		credits:   conn.grant(m.hdr.credits),
		flags:     m.hdr.flags&flagRelatedOps | flagServerToRedir,
		messageID: m.hdr.messageID,
		treeID:    m.hdr.treeID,
		sessionID: m.hdr.sessionID,
	}
	reply = append(reply, h.encode()...)
	return append(reply, body...), start
}

// errorResponse is the body of a failed command ([MS-SMB2] section 2.2.2).
// The structure counts one byte of variable data, so an empty error still
// carries a byte of padding.
func errorResponse() []byte {
	b := make([]byte, 9)
	binary.LittleEndian.PutUint16(b[0:], 9)
	return b
}

func (conn *connection) dispatch(ctx context.Context, m *message) ([]byte, uint32) {
	if m.hdr.command >= cmdCount {
		return nil, statusNotSupported
	}
	conn.mu.Lock()
	ready := conn.dialect != 0
	claimed := !conn.negotiated
	if m.hdr.command == cmdNegotiate {
		conn.negotiated = true
	}
	conn.mu.Unlock()

	if m.hdr.command == cmdNegotiate {
		// The claim is taken above rather than here, so that two negotiations
		// arriving together cannot both pass the test.
		if !claimed {
			return nil, statusInvalidParameter
		}
		return conn.negotiate(m)
	}
	if !ready {
		// Nothing may precede a negotiation ([MS-SMB2] section 3.3.5.2.7).
		return nil, statusInvalidParameter
	}
	switch m.hdr.command {
	case cmdEcho:
		return conn.echo(m)
	case cmdCancel:
		// Nothing this server does blocks on another client, so a cancel has
		// nothing to find. It carries no response either way.
		return nil, statusSuccess
	case cmdSessionSetup:
		return conn.sessionSetup(ctx, m)
	case cmdLogoff:
		return conn.logoff(m)
	case cmdTreeConnect:
		return conn.treeConnect(m)
	case cmdTreeDisconnect:
		return conn.treeDisconnect(m)
	case cmdCreate:
		return conn.create(ctx, m)
	case cmdClose:
		return conn.close(m)
	case cmdFlush:
		return conn.flush(m)
	case cmdRead:
		return conn.read(m)
	case cmdWrite:
		return conn.write(m)
	case cmdLock:
		return conn.lock(m)
	case cmdQueryDirectory:
		return conn.queryDirectory(ctx, m)
	case cmdQueryInfo:
		return conn.queryInfo(ctx, m)
	case cmdSetInfo:
		return conn.setInfo(ctx, m)
	case cmdIOCtl:
		return conn.ioctl(m)
	default:
		return nil, statusNotSupported
	}
}

// echo answers immediately ([MS-SMB2] section 2.2.29).
func (conn *connection) echo(m *message) ([]byte, uint32) {
	if len(m.body) < 4 || binary.LittleEndian.Uint16(m.body) != 4 {
		return nil, statusInvalidParameter
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:], 4)
	return b, statusSuccess
}
