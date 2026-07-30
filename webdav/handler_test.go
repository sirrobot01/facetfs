package webdav_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/webdav"
)

func TestFileWorkflow(t *testing.T) {
	handler := newHandler()

	response := serve(handler, http.MethodOptions, "/dav", nil, nil)
	if response.Code != http.StatusNoContent || response.Header().Get("DAV") != "1, 2" {
		t.Fatalf("OPTIONS = %d, DAV %q", response.Code, response.Header().Get("DAV"))
	}
	response = serve(handler, http.MethodPut, "/dav/file", strings.NewReader("hello world"), nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d: %s", response.Code, response.Body.String())
	}
	response = serve(handler, http.MethodGet, "/dav/file", nil, nil)
	if response.Code != http.StatusOK || response.Body.String() != "hello world" {
		t.Fatalf("GET = %d, %q", response.Code, response.Body.String())
	}
	etag := response.Header().Get("ETag")
	if etag == "" {
		t.Fatal("GET returned no ETag")
	}
	response = serve(handler, http.MethodGet, "/dav/file", nil, map[string]string{"Range": "bytes=6-10"})
	if response.Code != http.StatusPartialContent || response.Body.String() != "world" {
		t.Fatalf("range GET = %d, %q", response.Code, response.Body.String())
	}
	response = serve(handler, http.MethodGet, "/dav/file", nil, map[string]string{"If-None-Match": etag})
	if response.Code != http.StatusNotModified {
		t.Fatalf("conditional GET = %d", response.Code)
	}
	response = serve(handler, http.MethodGet, "/dav/file", nil, map[string]string{"Range": "bytes=0-4", "If-Range": "\"stale\""})
	if response.Code != http.StatusOK || response.Body.String() != "hello world" {
		t.Fatalf("stale If-Range GET = %d, %q", response.Code, response.Body.String())
	}
	response = serve(handler, http.MethodPut, "/dav/file", strings.NewReader("changed"), map[string]string{"If-Match": "\"wrong\""})
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("conditional PUT = %d", response.Code)
	}
	response = serve(handler, http.MethodPut, "/dav/file", strings.NewReader("changed"), map[string]string{"If-Match": "W/" + etag})
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("weak If-Match PUT = %d", response.Code)
	}
	response = serve(handler, http.MethodPut, "/dav/file", strings.NewReader("changed"), map[string]string{"If-Match": etag})
	if response.Code != http.StatusNoContent {
		t.Fatalf("overwrite PUT = %d: %s", response.Code, response.Body.String())
	}
	response = serve(handler, http.MethodHead, "/dav/file", nil, nil)
	if response.Code != http.StatusOK || response.Body.Len() != 0 || response.Header().Get("Content-Length") != "7" {
		t.Fatalf("HEAD = %d, len %d, header %q", response.Code, response.Body.Len(), response.Header().Get("Content-Length"))
	}
}

func TestCollectionWorkflow(t *testing.T) {
	handler := newHandler()
	if response := serve(handler, "MKCOL", "/dav/dir", nil, nil); response.Code != http.StatusCreated {
		t.Fatalf("MKCOL = %d: %s", response.Code, response.Body.String())
	}
	if response := serve(handler, http.MethodPut, "/dav/dir/file", strings.NewReader("data"), nil); response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d: %s", response.Code, response.Body.String())
	}
	response := serve(handler, "PROPFIND", "/dav/dir", nil, map[string]string{"Depth": "1"})
	if response.Code != http.StatusMultiStatus || !strings.Contains(response.Body.String(), "/dav/dir/file") {
		t.Fatalf("PROPFIND = %d: %s", response.Code, response.Body.String())
	}
	response = serve(handler, "MOVE", "/dav/dir/file", nil, map[string]string{"Destination": "http://example.com/dav/dir/moved"})
	if response.Code != http.StatusCreated {
		t.Fatalf("MOVE = %d: %s", response.Code, response.Body.String())
	}
	response = serve(handler, "COPY", "/dav/dir", nil, map[string]string{
		"Destination": "http://example.com/dav/copied", "Depth": "infinity",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("COPY = %d: %s", response.Code, response.Body.String())
	}
	response = serve(handler, http.MethodGet, "/dav/copied/moved", nil, nil)
	if response.Code != http.StatusOK || response.Body.String() != "data" {
		t.Fatalf("copied GET = %d, %q", response.Code, response.Body.String())
	}
	response = serve(handler, http.MethodDelete, "/dav/copied", nil, nil)
	if response.Code != http.StatusNoContent {
		t.Fatalf("recursive DELETE = %d: %s", response.Code, response.Body.String())
	}
	if response := serve(handler, http.MethodGet, "/dav/copied/moved", nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("GET after DELETE = %d", response.Code)
	}
}

const exclusiveWriteLock = `<?xml version="1.0" encoding="utf-8"?>` +
	`<lockinfo xmlns="DAV:"><lockscope><exclusive/></lockscope>` +
	`<locktype><write/></locktype><owner>tester</owner></lockinfo>`

func TestLockWorkflow(t *testing.T) {
	handler := newHandler()
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("hello"), nil); response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d: %s", response.Code, response.Body.String())
	}

	response := serve(handler, "LOCK", "/dav/file", strings.NewReader(exclusiveWriteLock), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("LOCK = %d: %s", response.Code, response.Body.String())
	}
	token := strings.Trim(response.Header().Get("Lock-Token"), "<>")
	if token == "" || !strings.Contains(response.Body.String(), token) {
		t.Fatalf("LOCK token = %q, body %s", token, response.Body.String())
	}

	// A second exclusive lock must conflict.
	if response := serve(handler, "LOCK", "/dav/file", strings.NewReader(exclusiveWriteLock), nil); response.Code != http.StatusLocked {
		t.Fatalf("conflicting LOCK = %d", response.Code)
	}
	// A write without the token is rejected.
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("changed"), nil); response.Code != http.StatusLocked {
		t.Fatalf("unlocked PUT = %d: %s", response.Code, response.Body.String())
	}
	// A write with the token succeeds.
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("changed"), map[string]string{"If": "(<" + token + ">)"}); response.Code != http.StatusNoContent {
		t.Fatalf("locked PUT = %d: %s", response.Code, response.Body.String())
	}
	// DELETE without the token is rejected; UNLOCK then release it.
	if response := serve(handler, http.MethodDelete, "/dav/file", nil, nil); response.Code != http.StatusLocked {
		t.Fatalf("unlocked DELETE = %d", response.Code)
	}
	if response := serve(handler, "UNLOCK", "/dav/file", nil, map[string]string{"Lock-Token": "<" + token + ">"}); response.Code != http.StatusNoContent {
		t.Fatalf("UNLOCK = %d: %s", response.Code, response.Body.String())
	}
	if response := serve(handler, http.MethodDelete, "/dav/file", nil, nil); response.Code != http.StatusNoContent {
		t.Fatalf("DELETE after UNLOCK = %d: %s", response.Code, response.Body.String())
	}
}

func TestLockCreatesEmptyResource(t *testing.T) {
	handler := newHandler()
	response := serve(handler, "LOCK", "/dav/pending", strings.NewReader(exclusiveWriteLock), nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("LOCK create = %d: %s", response.Code, response.Body.String())
	}
	token := strings.Trim(response.Header().Get("Lock-Token"), "<>")
	if response := serve(handler, http.MethodGet, "/dav/pending", nil, nil); response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("GET empty locked = %d, len %d", response.Code, response.Body.Len())
	}
	// The lock owner can write the pending resource.
	if response := serve(handler, http.MethodPut, "/dav/pending", strings.NewReader("body"), map[string]string{"If": "(<" + token + ">)"}); response.Code != http.StatusNoContent {
		t.Fatalf("locked PUT = %d: %s", response.Code, response.Body.String())
	}
}

// Only Depth 0 locks are granted, because the lock system enforces a lock on a
// single path. A lock must never report a depth it does not enforce.
func TestLockDepth(t *testing.T) {
	handler := newHandler()
	if response := serve(handler, "MKCOL", "/dav/coll", nil, nil); response.Code != http.StatusCreated {
		t.Fatalf("MKCOL = %d: %s", response.Code, response.Body.String())
	}

	// An explicit Depth infinity is refused rather than downgraded in silence.
	response := serve(handler, "LOCK", "/dav/coll", strings.NewReader(exclusiveWriteLock), map[string]string{"Depth": "infinity"})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("LOCK Depth infinity = %d, want 400: %s", response.Code, response.Body.String())
	}
	if response := serve(handler, "LOCK", "/dav/coll", strings.NewReader(exclusiveWriteLock), map[string]string{"Depth": "1"}); response.Code != http.StatusBadRequest {
		t.Fatalf("LOCK Depth 1 = %d, want 400", response.Code)
	}

	// An omitted Depth is granted as 0 and reported as 0, not as the RFC default
	// of infinity, so a client is never told it holds more than it does.
	response = serve(handler, "LOCK", "/dav/coll", strings.NewReader(exclusiveWriteLock), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("LOCK = %d: %s", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "<depth>0</depth>") {
		t.Fatalf("lockdiscovery depth not reported as 0: %s", body)
	}
	token := strings.Trim(response.Header().Get("Lock-Token"), "<>")

	// The Depth 0 collection lock is enforced where it claims to apply: adding an
	// internal member requires the token.
	if response := serve(handler, http.MethodPut, "/dav/coll/child", strings.NewReader("x"), nil); response.Code != http.StatusLocked {
		t.Fatalf("PUT into locked collection = %d, want 423", response.Code)
	}
	if response := serve(handler, http.MethodPut, "/dav/coll/child", strings.NewReader("x"), map[string]string{"If": "(<" + token + ">)"}); response.Code != http.StatusCreated {
		t.Fatalf("PUT with token = %d: %s", response.Code, response.Body.String())
	}
}

// refusingLS refuses every lock creation so the placeholder-cleanup path can
// be exercised.
type refusingLS struct{ webdav.LockSystem }

func (refusingLS) Create(time.Time, webdav.LockDetails) (webdav.LockDetails, error) {
	return webdav.LockDetails{}, webdav.ErrTooManyLocks
}

// LOCK on an unmapped URL creates an empty resource to carry the lock. If the
// lock is then refused, that placeholder must not survive: the client received
// an error and never asked for the resource.
func TestLockLeavesNoResourceWhenRefused(t *testing.T) {
	handler := &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: facetfs.NewMemFS(),
		LockSystem: refusingLS{webdav.NewMemLS()},
	}

	response := serve(handler, "LOCK", "/dav/pending", strings.NewReader(exclusiveWriteLock), nil)
	if response.Code != http.StatusLocked {
		t.Fatalf("refused LOCK = %d, want 423: %s", response.Code, response.Body.String())
	}
	if response := serve(handler, http.MethodGet, "/dav/pending", nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("GET after refused LOCK = %d, want 404: the placeholder was orphaned", response.Code)
	}
}

// A tagged list is evaluated against the resource it names rather than ignored.
func TestIfHeaderTaggedList(t *testing.T) {
	handler := newHandler()
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("v1"), nil); response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d: %s", response.Code, response.Body.String())
	}
	etag := serve(handler, http.MethodHead, "/dav/file", nil, nil).Header().Get("ETag")
	if etag == "" {
		t.Fatal("HEAD returned no ETag")
	}

	tagged := func(resource, condition string) map[string]string {
		return map[string]string{"If": "<http://example.com/dav/" + resource + "> (" + condition + ")"}
	}
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("v2"), tagged("file", "["+etag+"]")); response.Code != http.StatusNoContent {
		t.Fatalf("PUT tagged with a current etag = %d: %s", response.Code, response.Body.String())
	}
	// The etag has moved on, so the same list now fails instead of being skipped.
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("v3"), tagged("file", "["+etag+"]")); response.Code != http.StatusPreconditionFailed {
		t.Fatalf("PUT tagged with a stale etag = %d, want 412", response.Code)
	}
	// A list tagged for another resource governs that resource, not this one.
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("v4"), tagged("other", `["stale"]`)); response.Code != http.StatusNoContent {
		t.Fatalf("PUT tagged for another resource = %d, want 204", response.Code)
	}
}

// MKCOL, MOVE and COPY are governed by the locks on what they write, and submit
// their tokens through the If header like any other mutation.
func TestLockGovernsMkcolMoveAndCopy(t *testing.T) {
	handler := newHandler()
	if response := serve(handler, "MKCOL", "/dav/box", nil, nil); response.Code != http.StatusCreated {
		t.Fatalf("MKCOL = %d: %s", response.Code, response.Body.String())
	}
	lock := serve(handler, "LOCK", "/dav/box", strings.NewReader(exclusiveWriteLock), nil)
	if lock.Code != http.StatusOK {
		t.Fatalf("LOCK = %d: %s", lock.Code, lock.Body.String())
	}
	token := strings.Trim(lock.Header().Get("Lock-Token"), "<>")

	// MKCOL inside the locked collection. The new collection is the request-URI,
	// so an untagged list carries the token.
	if response := serve(handler, "MKCOL", "/dav/box/sub", nil, nil); response.Code != http.StatusLocked {
		t.Fatalf("MKCOL into a locked collection = %d, want 423", response.Code)
	}
	if response := serve(handler, "MKCOL", "/dav/box/sub", nil, map[string]string{"If": "(<" + token + ">)"}); response.Code != http.StatusCreated {
		t.Fatalf("MKCOL with the token = %d: %s", response.Code, response.Body.String())
	}

	// MOVE into the locked collection. The destination is not the request-URI, so
	// RFC 4918 §10.4.3 requires its token in a list tagged with it.
	if response := serve(handler, http.MethodPut, "/dav/free", strings.NewReader("x"), nil); response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d", response.Code)
	}
	move := map[string]string{"Destination": "http://example.com/dav/box/moved"}
	if response := serve(handler, "MOVE", "/dav/free", nil, move); response.Code != http.StatusLocked {
		t.Fatalf("MOVE into a locked collection = %d, want 423", response.Code)
	}
	move["If"] = "<http://example.com/dav/box/moved> (<" + token + ">)"
	if response := serve(handler, "MOVE", "/dav/free", nil, move); response.Code != http.StatusCreated {
		t.Fatalf("MOVE with the destination tagged = %d: %s", response.Code, response.Body.String())
	}

	// COPY onto a locked destination, which likewise needs a tagged list.
	if response := serve(handler, http.MethodPut, "/dav/source", strings.NewReader("y"), nil); response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d", response.Code)
	}
	copyTo := map[string]string{"Destination": "http://example.com/dav/box/moved"}
	if response := serve(handler, "COPY", "/dav/source", nil, copyTo); response.Code != http.StatusLocked {
		t.Fatalf("COPY onto a locked destination = %d, want 423", response.Code)
	}
	copyTo["If"] = "<http://example.com/dav/box/moved> (<" + token + ">)"
	if response := serve(handler, "COPY", "/dav/source", nil, copyTo); response.Code != http.StatusNoContent {
		t.Fatalf("COPY with the destination tagged = %d: %s", response.Code, response.Body.String())
	}
}

func TestLimitsAndTraversal(t *testing.T) {
	handler := &webdav.Handler{
		Prefix:       "/dav",
		FileSystem:   facetfs.NewMemFS(),
		LockSystem:   webdav.NewMemLS(),
		MaxBodyBytes: 4,
	}
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("12345"), nil); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized PUT = %d: %s", response.Code, response.Body.String())
	}
	if response := serve(handler, http.MethodGet, "/dav/a%2Fb", nil, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("encoded separator = %d", response.Code)
	}
	if response := serve(handler, http.MethodGet, "/other/file", nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("outside prefix = %d", response.Code)
	}
}

// A Handler without a LockSystem serves class 1 only.
func TestNilLockSystem(t *testing.T) {
	handler := &webdav.Handler{Prefix: "/dav", FileSystem: facetfs.NewMemFS()}
	response := serve(handler, http.MethodOptions, "/dav", nil, nil)
	if response.Code != http.StatusNoContent || response.Header().Get("DAV") != "1" {
		t.Fatalf("OPTIONS = %d, DAV %q", response.Code, response.Header().Get("DAV"))
	}
	if response := serve(handler, "LOCK", "/dav/file", strings.NewReader(exclusiveWriteLock), nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("LOCK without LockSystem = %d, want 405", response.Code)
	}
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("data"), nil); response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d: %s", response.Code, response.Body.String())
	}
}

func newHandler() http.Handler {
	return &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: facetfs.NewMemFS(),
		LockSystem: webdav.NewMemLS(),
	}
}

func serve(handler http.Handler, method, target string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, body)
	request.Host = "example.com"
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// PROPPATCH parses the body, honors locks, and refuses every property change
// atomically with a 403 propstat: dead properties are not stored.
func TestProppatch(t *testing.T) {
	handler := newHandler()
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("v"), nil); response.Code != http.StatusCreated {
		t.Fatalf("PUT = %d", response.Code)
	}
	patch := `<?xml version="1.0"?><propertyupdate xmlns="DAV:" xmlns:z="urn:z">` +
		`<set><prop><z:author>me</z:author></prop></set></propertyupdate>`
	response := serve(handler, "PROPPATCH", "/dav/file", strings.NewReader(patch), nil)
	if response.Code != http.StatusMultiStatus || !strings.Contains(response.Body.String(), "403 Forbidden") {
		t.Fatalf("PROPPATCH = %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "author") {
		t.Fatalf("PROPPATCH response does not name the property: %s", response.Body.String())
	}

	lock := serve(handler, "LOCK", "/dav/file", strings.NewReader(exclusiveWriteLock), nil)
	if lock.Code != http.StatusOK {
		t.Fatalf("LOCK = %d", lock.Code)
	}
	if response := serve(handler, "PROPPATCH", "/dav/file", strings.NewReader(patch), nil); response.Code != http.StatusLocked {
		t.Fatalf("PROPPATCH on locked resource = %d, want 423", response.Code)
	}

	if response := serve(handler, "PROPPATCH", "/dav/missing", strings.NewReader(patch), nil); response.Code != http.StatusNotFound {
		t.Fatalf("PROPPATCH on missing resource = %d, want 404", response.Code)
	}
}

// A PROPFIND body with an illegal empty namespace declaration is rejected.
func TestPropfindInvalidNamespace(t *testing.T) {
	handler := newHandler()
	body := `<?xml version="1.0"?><propfind xmlns="DAV:"><prop><foo:bar xmlns:foo=""/></prop></propfind>`
	if response := serve(handler, "PROPFIND", "/dav/", strings.NewReader(body), map[string]string{"Depth": "0"}); response.Code != http.StatusBadRequest {
		t.Fatalf("PROPFIND with empty prefixed xmlns = %d, want 400", response.Code)
	}
}
