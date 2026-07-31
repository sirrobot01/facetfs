package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/sirrobot01/facetfs"
)

type passwordAuth struct{ hashes map[string][]byte }

func (a passwordAuth) NTHash(_ context.Context, domain, user string) ([]byte, error) {
	if h := a.hashes[domain+"\\"+user]; h != nil {
		return append([]byte(nil), h...), nil
	}
	return nil, errors.New("unknown user")
}

func type1Message() []byte {
	b := make([]byte, 16)
	copy(b, ntlmSignature)
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], ntlmNegotiateUnicode|ntlmNegotiateNTLM|ntlmNegotiateExtendedSessionSecurity|ntlmNegotiateSign|ntlmNegotiateAlwaysSign)
	return b
}

func sessionSetupRequest(token []byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, 25)
	b[3] = signingEnabled
	binary.LittleEndian.PutUint16(b[12:], headerSize+24)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(token)))
	return append(b, token...)
}

func type3Message(t testing.TB, domain, user string, ntHash []byte, challenge [8]byte) ([]byte, []byte) {
	t.Helper()
	blob := make([]byte, 28)
	binary.LittleEndian.PutUint32(blob, 0x00000101)
	binary.LittleEndian.PutUint64(blob[8:], fileTimeEpoch+123456789)
	copy(blob[16:], []byte("client42"))
	blob = append(blob, 0, 0, 0, 0)
	responseKey := ntlmResponseKey(ntHash, user, domain)
	proof := hmacMD5(responseKey, challenge[:], blob)
	ntResponse := append(append([]byte(nil), proof...), blob...)
	sessionKey := hmacMD5(responseKey, proof)
	domainWire, userWire := utf16Bytes(domain), utf16Bytes(user)
	const fixed = 64
	b := make([]byte, fixed)
	copy(b, ntlmSignature)
	binary.LittleEndian.PutUint32(b[8:], 3)
	off := fixed
	putSecurityBuffer(b[20:], uint16(len(ntResponse)), off)
	b = append(b, ntResponse...)
	off += len(ntResponse)
	putSecurityBuffer(b[28:], uint16(len(domainWire)), off)
	b = append(b, domainWire...)
	off += len(domainWire)
	putSecurityBuffer(b[36:], uint16(len(userWire)), off)
	b = append(b, userWire...)
	putSecurityBuffer(b[44:], 0, fixed)
	putSecurityBuffer(b[52:], 0, fixed)
	binary.LittleEndian.PutUint32(b[60:], ntlmNegotiateUnicode|ntlmNegotiateNTLM|ntlmNegotiateExtendedSessionSecurity|ntlmNegotiateSign|ntlmNegotiateAlwaysSign)
	return b, sessionKey
}

type authClient struct {
	*testClient
	session uint64
	tree    uint32
	key     []byte
	alg     uint16
}

func newAuthClient(t testing.TB) *authClient {
	t.Helper()
	hash := NTHash("correct horse battery staple")
	s := &Server{FileSystem: facetfs.NewMemFS(), Authenticator: passwordAuth{hashes: map[string][]byte{"DOMAIN\\alice": hash}}}
	return auth210(newTestClientFor(t, s), hash)
}

// auth210 negotiates dialect 2.1 on an established raw client and
// authenticates alice, whose NT hash the server's Authenticator must hold.
func auth210(tc *testClient, hash []byte) *authClient {
	t := tc.t
	t.Helper()
	if h, _ := tc.negotiate([]uint16{dialect210}, false); h.status != statusSuccess {
		t.Fatalf("NEGOTIATE = %#x", h.status)
	}
	tc.send(tc.request(cmdSessionSetup, sessionSetupRequest(type1Message())))
	h, body := tc.recv()
	if h.status != statusMoreProcessingRequired || h.sessionID == 0 {
		t.Fatalf("first SESSION_SETUP = %#x, session %#x", h.status, h.sessionID)
	}
	token, ok := ntlmToken(body)
	if !ok || len(token) < 32 {
		t.Fatalf("challenge token = %x", body)
	}
	var challenge [8]byte
	copy(challenge[:], token[24:32])
	type3, key := type3Message(t, "DOMAIN", "alice", hash, challenge)
	req := tc.request(cmdSessionSetup, sessionSetupRequest(type3))
	binary.LittleEndian.PutUint64(req[40:], h.sessionID)
	tc.send(req)
	frame, err := readFrame(tc.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	final, ok := decodeHeader(frame)
	if !ok || final.status != statusSuccess || !verifyMessage(key, signHMACSHA256, frame) {
		t.Fatalf("final SESSION_SETUP = %+v, signature valid %v", final, verifyMessage(key, signHMACSHA256, frame))
	}
	ac := &authClient{testClient: tc, session: h.sessionID, key: key, alg: signHMACSHA256}
	ac.connectTree()
	return ac
}

func (ac *authClient) connectTree() {
	ac.t.Helper()
	unc := utf16Bytes("\\\\FACETFS\\share")
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b, 9)
	binary.LittleEndian.PutUint16(b[4:], headerSize+8)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(unc)))
	h, _ := ac.exchange(cmdTreeConnect, append(b, unc...))
	if h.status != statusSuccess || h.treeID == 0 {
		ac.t.Fatalf("TREE_CONNECT = %#x, tree %#x", h.status, h.treeID)
	}
	ac.tree = h.treeID
}

func (ac *authClient) exchange(command uint16, body []byte) (header, []byte) {
	ac.t.Helper()
	req := ac.request(command, body)
	binary.LittleEndian.PutUint32(req[36:], ac.tree)
	binary.LittleEndian.PutUint64(req[40:], ac.session)
	if !signMessage(ac.key, ac.alg, req) {
		ac.t.Fatal("sign request")
	}
	ac.send(req)
	frame, err := readFrame(ac.c, 2<<20)
	if err != nil {
		ac.t.Fatal(err)
	}
	if !verifyMessage(ac.key, ac.alg, frame) {
		ac.t.Fatal("server response signature did not verify")
	}
	h, ok := decodeHeader(frame)
	if !ok {
		ac.t.Fatal("response header")
	}
	return h, frame[headerSize:]
}

func newAuthClient311(t testing.TB) *authClient {
	t.Helper()
	hash := NTHash("correct horse battery staple")
	s := &Server{FileSystem: facetfs.NewMemFS(), Authenticator: passwordAuth{hashes: map[string][]byte{"DOMAIN\\alice": hash}}}
	return auth311(newTestClientFor(t, s), hash)
}

// auth311 is auth210 for dialect 3.1.1: it carries the negotiate contexts,
// keeps the pre-authentication hash, and derives the CMAC signing key.
func auth311(tc *testClient, hash []byte) *authClient {
	t := tc.t
	t.Helper()
	request := tc.request(cmdNegotiate, negotiateRequest([]uint16{dialect311}, true))
	tc.send(request)
	response, err := readFrame(tc.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := decodeHeader(response)
	if !ok || h.status != statusSuccess {
		t.Fatalf("NEGOTIATE 3.1.1 = %+v", h)
	}
	var preauth [preauthHashSize]byte
	preauth = advancePreauth(preauth, request)
	preauth = advancePreauth(preauth, response)

	first := tc.request(cmdSessionSetup, sessionSetupRequest(type1Message()))
	tc.send(first)
	challengeResponse, err := readFrame(tc.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	h, ok = decodeHeader(challengeResponse)
	if !ok || h.status != statusMoreProcessingRequired {
		t.Fatalf("first SESSION_SETUP = %+v", h)
	}
	preauth = advancePreauth(preauth, first)
	preauth = advancePreauth(preauth, challengeResponse)
	token, ok := ntlmToken(challengeResponse)
	if !ok || len(token) < 32 {
		t.Fatalf("challenge token = %x", challengeResponse)
	}
	var challenge [8]byte
	copy(challenge[:], token[24:32])
	type3, sessionKey := type3Message(t, "DOMAIN", "alice", hash, challenge)
	finalRequest := tc.request(cmdSessionSetup, sessionSetupRequest(type3))
	binary.LittleEndian.PutUint64(finalRequest[40:], h.sessionID)
	preauth = advancePreauth(preauth, finalRequest)
	key := smbKDF(sessionKey, "SMBSigningKey", preauth[:])
	tc.send(finalRequest)
	finalResponse, err := readFrame(tc.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	final, ok := decodeHeader(finalResponse)
	if !ok || final.status != statusSuccess || !verifyMessage(key, signAESCMAC, finalResponse) {
		t.Fatalf("final 3.1.1 SESSION_SETUP = %+v", final)
	}
	ac := &authClient{testClient: tc, session: h.sessionID, key: key, alg: signAESCMAC}
	ac.connectTree()
	return ac
}

func TestSMB311PreauthAndCMACSession(t *testing.T) {
	ac := newAuthClient311(t)
	h, _ := ac.exchange(cmdEcho, echoRequest())
	if h.status != statusSuccess {
		t.Fatalf("signed SMB 3.1.1 ECHO = %#x", h.status)
	}
}

func TestSignedCompoundChainSignsEachMessage(t *testing.T) {
	ac := newAuthClient(t)

	// Each message of the chain carries its own signature, computed over its
	// header, its body, and its padding ([MS-SMB2] section 3.1.4.1).
	first := ac.request(cmdEcho, echoRequest())
	binary.LittleEndian.PutUint64(first[40:], ac.session)
	for len(first)%8 != 0 {
		first = append(first, 0)
	}
	binary.LittleEndian.PutUint32(first[20:], uint32(len(first)))
	if !signMessage(ac.key, ac.alg, first) {
		t.Fatal("sign first request")
	}
	second := ac.request(cmdEcho, echoRequest())
	binary.LittleEndian.PutUint64(second[40:], ac.session)
	if !signMessage(ac.key, ac.alg, second) {
		t.Fatal("sign second request")
	}
	ac.send(append(first, second...))

	frame, err := readFrame(ac.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	h1, ok := decodeHeader(frame)
	if !ok || h1.status != statusSuccess || h1.nextCommand == 0 {
		t.Fatalf("first signed reply = %+v", h1)
	}
	if !verifyMessage(ac.key, ac.alg, frame[:h1.nextCommand]) {
		t.Fatal("first reply is not signed on its own")
	}
	h2, ok := decodeHeader(frame[h1.nextCommand:])
	if !ok || h2.status != statusSuccess || h2.nextCommand != 0 {
		t.Fatalf("second signed reply = %+v", h2)
	}
	if !verifyMessage(ac.key, ac.alg, frame[h1.nextCommand:]) {
		t.Fatal("second reply is not signed on its own")
	}
}

func TestBadSessionSignatureIsDeniedAndClosed(t *testing.T) {
	ac := newAuthClient(t)
	req := ac.request(cmdEcho, echoRequest())
	binary.LittleEndian.PutUint32(req[36:], ac.tree)
	binary.LittleEndian.PutUint64(req[40:], ac.session)
	ac.send(req) // deliberately unsigned
	frame, err := readFrame(ac.c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := decodeHeader(frame)
	if !ok || h.status != statusAccessDenied || !verifyMessage(ac.key, ac.alg, frame) {
		t.Fatalf("bad signature response = %+v, decoded %v", h, ok)
	}
	if _, err := readFrame(ac.c, 1<<20); err == nil {
		t.Fatal("connection remained open after a bad signature")
	}
}

func createRequest(name string, disposition, options uint32) []byte {
	wire := utf16Bytes(name)
	b := make([]byte, 56)
	binary.LittleEndian.PutUint16(b, 57)
	binary.LittleEndian.PutUint32(b[24:], accessGenericRead|accessGenericWrite|accessDelete)
	binary.LittleEndian.PutUint32(b[32:], shareRead|shareWrite|shareDelete)
	binary.LittleEndian.PutUint32(b[36:], disposition)
	binary.LittleEndian.PutUint32(b[40:], options)
	if len(wire) != 0 {
		binary.LittleEndian.PutUint16(b[44:], headerSize+56)
		binary.LittleEndian.PutUint16(b[46:], uint16(len(wire)))
	}
	return append(b, wire...)
}

func TestAuthenticatedCreateWriteReadClose(t *testing.T) {
	ac := newAuthClient(t)
	h, body := ac.exchange(cmdCreate, createRequest("hello.txt", fileOverwriteIf, fileNonDirectoryFile))
	if h.status != statusSuccess || len(body) < 88 {
		t.Fatalf("CREATE = %#x, body %d", h.status, len(body))
	}
	var id [16]byte
	copy(id[:], body[64:80])

	data := []byte("facetfs over smb")
	write := make([]byte, 48)
	binary.LittleEndian.PutUint16(write, 49)
	binary.LittleEndian.PutUint16(write[2:], headerSize+48)
	binary.LittleEndian.PutUint32(write[4:], uint32(len(data)))
	copy(write[16:], id[:])
	h, _ = ac.exchange(cmdWrite, append(write, data...))
	if h.status != statusSuccess {
		t.Fatalf("WRITE = %#x", h.status)
	}

	read := make([]byte, 48)
	binary.LittleEndian.PutUint16(read, 49)
	binary.LittleEndian.PutUint32(read[4:], uint32(len(data)))
	copy(read[16:], id[:])
	h, body = ac.exchange(cmdRead, read)
	if h.status != statusSuccess || len(body) < 16 || !bytes.Equal(body[16:16+len(data)], data) {
		t.Fatalf("READ = %#x, body %x", h.status, body)
	}

	closeBody := make([]byte, 24)
	binary.LittleEndian.PutUint16(closeBody, 24)
	copy(closeBody[8:], id[:])
	h, _ = ac.exchange(cmdClose, closeBody)
	if h.status != statusSuccess {
		t.Fatalf("CLOSE = %#x", h.status)
	}
	got, err := ac.s.FileSystem.OpenFile(t.Context(), "/hello.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(data))
	if _, err := io.ReadFull(got, b); err != nil || !bytes.Equal(b, data) {
		t.Fatalf("filesystem data = %q, %v", b, err)
	}
	got.Close()

	h, body = ac.exchange(cmdCreate, createRequest("", fileOpen, fileDirectoryFile))
	if h.status != statusSuccess || len(body) < 80 {
		t.Fatalf("open root = %#x", h.status)
	}
	copy(id[:], body[64:80])
	pattern := utf16Bytes("*")
	query := make([]byte, 32)
	binary.LittleEndian.PutUint16(query, 33)
	query[2], query[3] = 3, 1 // FileBothDirectoryInformation, RESTART_SCANS
	copy(query[8:], id[:])
	binary.LittleEndian.PutUint16(query[24:], headerSize+32)
	binary.LittleEndian.PutUint16(query[26:], uint16(len(pattern)))
	binary.LittleEndian.PutUint32(query[28:], 4096)
	h, body = ac.exchange(cmdQueryDirectory, append(query, pattern...))
	if h.status != statusSuccess || !bytes.Contains(body, utf16Bytes("hello.txt")) {
		t.Fatalf("QUERY_DIRECTORY = %#x, body %x", h.status, body)
	}
}

func responseFileID(t testing.TB, h header, body []byte) [16]byte {
	t.Helper()
	if h.status != statusSuccess || len(body) < 80 {
		t.Fatalf("CREATE = %#x, body %d", h.status, len(body))
	}
	var id [16]byte
	copy(id[:], body[64:80])
	return id
}

func closeRequest(id [16]byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, 24)
	copy(b[8:], id[:])
	return b
}

func TestShareConflictDoesNotTruncateFile(t *testing.T) {
	ac := newAuthClient(t)
	first := createRequest("exclusive.txt", fileOverwriteIf, fileNonDirectoryFile)
	binary.LittleEndian.PutUint32(first[32:], 0)
	h, body := ac.exchange(cmdCreate, first)
	id := responseFileID(t, h, body)
	data := []byte("keep me")
	write := make([]byte, 48)
	binary.LittleEndian.PutUint16(write, 49)
	binary.LittleEndian.PutUint16(write[2:], headerSize+48)
	binary.LittleEndian.PutUint32(write[4:], uint32(len(data)))
	copy(write[16:], id[:])
	if h, _ := ac.exchange(cmdWrite, append(write, data...)); h.status != statusSuccess {
		t.Fatalf("WRITE = %#x", h.status)
	}
	h, _ = ac.exchange(cmdCreate, createRequest("exclusive.txt", fileOverwriteIf, fileNonDirectoryFile))
	if h.status != statusSharingViolation {
		t.Fatalf("conflicting CREATE = %#x", h.status)
	}
	if h, _ := ac.exchange(cmdClose, closeRequest(id)); h.status != statusSuccess {
		t.Fatalf("CLOSE = %#x", h.status)
	}
	f, err := ac.s.FileSystem.OpenFile(t.Context(), "/exclusive.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("data after conflict = %q, %v", got, err)
	}
}

func lockRequest(id [16]byte, flags uint32) []byte {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint16(b, 48)
	binary.LittleEndian.PutUint16(b[2:], 1)
	copy(b[8:], id[:])
	binary.LittleEndian.PutUint64(b[24:], 0)
	binary.LittleEndian.PutUint64(b[32:], 16)
	binary.LittleEndian.PutUint32(b[40:], flags)
	return b
}

func TestProtocolByteRangeLockConflict(t *testing.T) {
	ac := newAuthClient(t)
	h, body := ac.exchange(cmdCreate, createRequest("locked.txt", fileOpenIf, fileNonDirectoryFile))
	first := responseFileID(t, h, body)
	h, body = ac.exchange(cmdCreate, createRequest("locked.txt", fileOpen, fileNonDirectoryFile))
	second := responseFileID(t, h, body)
	if h, _ := ac.exchange(cmdLock, lockRequest(first, 0x12)); h.status != statusSuccess {
		t.Fatalf("exclusive LOCK = %#x", h.status)
	}
	if h, _ := ac.exchange(cmdLock, lockRequest(second, 0x11)); h.status != statusLockNotGranted {
		t.Fatalf("conflicting LOCK = %#x", h.status)
	}
	if h, _ := ac.exchange(cmdLock, lockRequest(first, 0x04)); h.status != statusSuccess {
		t.Fatalf("UNLOCK = %#x", h.status)
	}
}

func TestSMBPathValidation(t *testing.T) {
	for _, bad := range []string{"..\\escape", "CON", "folder\\NUL.txt", "a/b"} {
		if _, err := smbPath(utf16Bytes(bad)); !errors.Is(err, errSMBName) {
			t.Errorf("smbPath(%q) = %v", bad, err)
		}
	}
	if got, err := smbPath(utf16Bytes("dir\\file.txt")); err != nil || got != "/dir/file.txt" {
		t.Fatalf("valid path = %q, %v", got, err)
	}
}

func TestShareModeAndLockState(t *testing.T) {
	st := newServerState(&Server{FileSystem: facetfs.NewMemFS()})
	s := &session{handles: make(map[[16]byte]*openHandle), snapshots: make(map[[16]byte]*dirSnapshot)}
	st.sessions[s.id] = s
	h1 := &openHandle{session: s, path: "/x", access: accessGenericRead, share: shareRead}
	if got := st.addHandle(s, h1); got != statusSuccess {
		t.Fatalf("first open = %#x", got)
	}
	h2 := &openHandle{session: s, path: "/x", access: accessGenericWrite, share: shareRead | shareWrite}
	if got := st.addHandle(s, h2); got != statusSharingViolation {
		t.Fatalf("conflicting open = %#x", got)
	}
}
