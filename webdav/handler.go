// Package webdav provides a WebDAV handler (RFC 4918) that serves a
// facetfs.FileSystem over HTTP. The caller owns the HTTP server, transport
// security, and authentication.
//
// The handler deviates from RFC 4918 in three documented ways. Locks are
// exclusive write locks with Depth 0 only; a shared-lock or Depth-infinity
// LOCK is refused rather than downgraded. Dead properties are not stored;
// PROPPATCH enforces lock and If preconditions, then refuses every property
// change atomically with a 403 propstat. Entity tags derive from modification
// time and size, so a FileSystem whose ModTime is coarse yields weak change
// detection.
package webdav

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
)

const (
	defaultBodyLimit     = 1 << 30
	defaultTraversalSize = 10_000
	defaultResponseLimit = 16 << 20
)

// errCrossHost reports a COPY or MOVE Destination on another server.
var errCrossHost = errors.New("webdav: destination is on another host")

// errWalkLimit reports that a traversal visited more entries than the handler
// allows.
var errWalkLimit = errors.New("webdav: too many entries")

// Handler serves a FileSystem over WebDAV. The zero value of every optional
// field is usable.
type Handler struct {
	// Prefix is the URL path prefix stripped from request paths. Optional.
	Prefix string
	// FileSystem is the served filesystem. Required.
	FileSystem facetfs.FileSystem
	// LockSystem supports WebDAV Class 2 locking. When nil, LOCK and UNLOCK
	// return 405 Method Not Allowed and OPTIONS advertises class 1 only.
	LockSystem LockSystem
	// MaxBodyBytes caps a PUT body. Zero means 1 GiB.
	MaxBodyBytes int64
	// MaxWalkNodes caps the entries visited by PROPFIND and COPY traversals.
	// Zero means 10 000.
	MaxWalkNodes int
	// MaxResponseBytes caps a PROPFIND response. Zero means 16 MiB.
	MaxResponseBytes int64
	// Logger, if set, receives errors that produced a 5xx response.
	Logger func(*http.Request, error)
}

func (h *Handler) maxBodyBytes() int64 {
	if h.MaxBodyBytes > 0 {
		return h.MaxBodyBytes
	}
	return defaultBodyLimit
}

func (h *Handler) maxWalkNodes() int {
	if h.MaxWalkNodes > 0 {
		return h.MaxWalkNodes
	}
	return defaultTraversalSize
}

func (h *Handler) maxResponseBytes() int64 {
	if h.MaxResponseBytes > 0 {
		return h.MaxResponseBytes
	}
	return defaultResponseLimit
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.FileSystem == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	segments, err := h.segments(r.URL)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	switch r.Method {
	case http.MethodOptions:
		h.options(w)
	case http.MethodGet, http.MethodHead:
		h.get(w, r, segments)
	case http.MethodPut:
		h.put(w, r, segments)
	case "MKCOL":
		h.mkcol(w, r, segments)
	case http.MethodDelete:
		h.remove(w, r, segments)
	case "MOVE":
		h.move(w, r, segments)
	case "COPY":
		h.copy(w, r, segments)
	case "PROPFIND":
		h.propfind(w, r, segments)
	case "PROPPATCH":
		h.proppatch(w, r, segments)
	case "LOCK":
		if h.LockSystem == nil {
			h.methodNotAllowed(w)
			return
		}
		h.lock(w, r, segments)
	case "UNLOCK":
		if h.LockSystem == nil {
			h.methodNotAllowed(w)
			return
		}
		h.unlock(w, r, segments)
	default:
		h.methodNotAllowed(w)
	}
}

func (h *Handler) methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", h.allowMethods())
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func (h *Handler) allowMethods() string {
	methods := "OPTIONS, PROPFIND, PROPPATCH, GET, HEAD, PUT, MKCOL, DELETE, COPY, MOVE"
	if h.LockSystem != nil {
		methods += ", LOCK, UNLOCK"
	}
	return methods
}

// fsPath joins validated segments into the slash-rooted path passed to the
// FileSystem.
func fsPath(segments []string) string {
	return "/" + strings.Join(segments, "/")
}

func (h *Handler) prefixPath() string {
	prefix := path.Clean("/" + strings.Trim(h.Prefix, "/"))
	if prefix == "." {
		return "/"
	}
	return prefix
}

func (h *Handler) segments(u *url.URL) ([]string, error) {
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return nil, fs.ErrInvalid
	}
	requestPath := u.Path
	if prefix := h.prefixPath(); prefix != "/" {
		if requestPath != prefix && !strings.HasPrefix(requestPath, prefix+"/") {
			return nil, fs.ErrNotExist
		}
		requestPath = strings.TrimPrefix(requestPath, prefix)
	}
	requestPath = strings.Trim(requestPath, "/")
	if requestPath == "" {
		return nil, nil
	}
	segments := strings.Split(requestPath, "/")
	for _, segment := range segments {
		if err := names.Validate(segment); err != nil {
			return nil, err
		}
		if strings.Contains(segment, "\\") {
			return nil, fs.ErrInvalid
		}
	}
	return segments, nil
}

func (h *Handler) options(w http.ResponseWriter) {
	dav := "1"
	if h.LockSystem != nil {
		dav = "1, 2"
	}
	w.Header().Set("DAV", dav)
	w.Header().Set("Allow", h.allowMethods())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	switch {
	case errors.Is(err, fs.ErrNotExist):
		status = http.StatusNotFound
	case errors.Is(err, fs.ErrPermission):
		status = http.StatusForbidden
	case errors.Is(err, fs.ErrExist):
		status = http.StatusConflict
	case errors.Is(err, fs.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, ErrLocked), errors.Is(err, ErrTooManyLocks):
		status = http.StatusLocked
	case errors.Is(err, errCrossHost):
		status = http.StatusBadGateway
	case errors.Is(err, errWalkLimit):
		status = http.StatusInsufficientStorage
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return
	default:
		status = http.StatusInternalServerError
		if h.Logger != nil {
			h.Logger(r, err)
		}
	}
	http.Error(w, http.StatusText(status), status)
}

func (h *Handler) now() time.Time {
	return time.Now()
}

func destinationURL(r *http.Request) (*url.URL, error) {
	destination := r.Header.Get("Destination")
	if destination == "" {
		return nil, fs.ErrInvalid
	}
	u, err := url.Parse(destination)
	if err != nil || u.User != nil || u.Fragment != "" {
		return nil, fs.ErrInvalid
	}
	if u.IsAbs() && u.Scheme != "http" && u.Scheme != "https" {
		return nil, errCrossHost
	}
	if u.IsAbs() && !strings.EqualFold(u.Host, r.Host) {
		return nil, errCrossHost
	}
	return u, nil
}
