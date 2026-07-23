package webdav_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/memfs"
	"github.com/sirrobot01/facetfs/webdav"
)

func TestFileWorkflow(t *testing.T) {
	handler := newHandler(t, webdav.Options{ExportID: "data", Prefix: "/dav"})

	response := serve(handler, http.MethodOptions, "/dav", nil, nil)
	if response.Code != http.StatusNoContent || response.Header().Get("DAV") != "1" {
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
	handler := newHandler(t, webdav.Options{ExportID: "data", Prefix: "/dav"})
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

func TestLimitsAndTraversal(t *testing.T) {
	handler := newHandler(t, webdav.Options{ExportID: "data", Prefix: "/dav", MaxBodyBytes: 4})
	if response := serve(handler, http.MethodPut, "/dav/file", strings.NewReader("12345"), nil); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized PUT = %d: %s", response.Code, response.Body.String())
	}
	if response := serve(handler, http.MethodGet, "/dav/a%2Fb", nil, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("encoded separator = %d", response.Code)
	}
	if response := serve(handler, http.MethodGet, "/dav/e%CC%81", nil, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("non-normalized path = %d", response.Code)
	}
	if response := serve(handler, http.MethodGet, "/other/file", nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("outside prefix = %d", response.Code)
	}
}

func TestAuthenticationFailure(t *testing.T) {
	server, err := facetfs.New(t.Context(), facetfs.Config{Exports: []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := webdav.New(server, webdav.Options{ExportID: "data"})
	if err != nil {
		t.Fatal(err)
	}
	if response := serve(handler, http.MethodGet, "/file", nil, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET = %d", response.Code)
	}
}

func TestPlaintextBasicAuthenticationIsRejected(t *testing.T) {
	handler := newHandler(t, webdav.Options{
		ExportID: "data",
		Authenticate: func(context.Context, *http.Request) (facetfs.Principal, error) {
			return facetfs.Principal{Subject: "user"}, nil
		},
	})
	response := serve(handler, http.MethodGet, "/file", nil, map[string]string{"Authorization": "Basic dXNlcjpwYXNz"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("plaintext Basic GET = %d", response.Code)
	}
}

func newHandler(t *testing.T, options webdav.Options) http.Handler {
	t.Helper()
	server, err := facetfs.New(t.Context(), facetfs.Config{
		Authorizer: facetfs.AuthorizerFunc(func(context.Context, facetfs.Request, facetfs.AccessCheck) error { return nil }),
		Exports:    []facetfs.Export{{ID: "data", Name: "Data", Backend: memfs.New()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := webdav.New(server, options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
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
