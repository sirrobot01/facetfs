// Package webdav provides an HTTP handler for FacetFS exports.
package webdav

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
	"golang.org/x/text/unicode/norm"
)

const (
	defaultBodyLimit     = 1 << 30
	defaultTraversalSize = 10_000
	defaultResponseLimit = 16 << 20
)

type Authenticator func(context.Context, *http.Request) (facetfs.Principal, error)

type Options struct {
	ExportID           string
	Prefix             string
	Authenticate       Authenticator
	AllowInsecureBasic bool
	MaxBodyBytes       int64
	MaxWalkNodes       int
	MaxResponseBytes   int64
}

type Handler struct {
	server             *facetfs.Server
	exportID           string
	prefix             string
	authenticate       Authenticator
	allowInsecureBasic bool
	maxBodyBytes       int64
	maxWalkNodes       int
	maxResponseBytes   int64
}

func New(server *facetfs.Server, options Options) (*Handler, error) {
	if server == nil || options.ExportID == "" {
		return nil, facetfs.ErrInvalid
	}
	prefix := path.Clean("/" + strings.Trim(options.Prefix, "/"))
	if prefix == "." {
		prefix = "/"
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = defaultBodyLimit
	}
	if options.MaxWalkNodes <= 0 {
		options.MaxWalkNodes = defaultTraversalSize
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = defaultResponseLimit
	}
	return &Handler{
		server: server, exportID: options.ExportID, prefix: prefix, authenticate: options.Authenticate,
		allowInsecureBasic: options.AllowInsecureBasic,
		maxBodyBytes:       options.MaxBodyBytes, maxWalkNodes: options.MaxWalkNodes, maxResponseBytes: options.MaxResponseBytes,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, err := h.request(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	defer h.server.CloseSession(context.WithoutCancel(r.Context()), request.SessionID)
	segments, err := h.segments(r.URL)
	if err != nil {
		h.writeError(w, err)
		return
	}

	switch r.Method {
	case http.MethodOptions:
		h.options(w)
	case http.MethodGet, http.MethodHead:
		h.get(w, r, request, segments)
	case http.MethodPut:
		h.put(w, r, request, segments)
	case "MKCOL":
		h.mkcol(w, r, request, segments)
	case http.MethodDelete:
		h.remove(w, r, request, segments)
	case "MOVE":
		h.move(w, r, request, segments)
	case "COPY":
		h.copy(w, r, request, segments)
	case "PROPFIND":
		h.propfind(w, r, request, segments)
	default:
		w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, COPY, MOVE")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (h *Handler) request(r *http.Request) (facetfs.Request, error) {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "basic ") && r.TLS == nil && !h.allowInsecureBasic {
		return facetfs.Request{}, facetfs.ErrAccessDenied
	}
	var principal facetfs.Principal
	if h.authenticate != nil {
		var err error
		principal, err = h.authenticate(r.Context(), r)
		if err != nil {
			return facetfs.Request{}, err
		}
	}
	return facetfs.Request{
		Principal:  principal,
		Protocol:   facetfs.ProtocolWebDAV,
		ClientID:   r.RemoteAddr,
		SessionID:  rand.Text(),
		RemoteAddr: stringAddr(r.RemoteAddr),
	}, nil
}

func (h *Handler) segments(u *url.URL) ([]string, error) {
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return nil, facetfs.ErrInvalid
	}
	requestPath := u.Path
	if h.prefix != "/" {
		if requestPath != h.prefix && !strings.HasPrefix(requestPath, h.prefix+"/") {
			return nil, facetfs.ErrNotFound
		}
		requestPath = strings.TrimPrefix(requestPath, h.prefix)
	}
	requestPath = strings.Trim(requestPath, "/")
	if requestPath == "" {
		return nil, nil
	}
	segments := strings.Split(requestPath, "/")
	for _, segment := range segments {
		if err := names.Validate(segment); err != nil || strings.Contains(segment, "\\") || !norm.NFC.IsNormalString(segment) {
			if err == nil {
				err = facetfs.ErrInvalid
			}
			return nil, err
		}
	}
	return segments, nil
}

func (h *Handler) resolve(ctx context.Context, request facetfs.Request, segments []string) (facetfs.ObjectRef, facetfs.Attr, error) {
	object, attr, err := h.server.Root(ctx, request, h.exportID)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	for _, segment := range segments {
		object, attr, err = h.server.Lookup(ctx, request, object, segment)
		if err != nil {
			return facetfs.ObjectRef{}, facetfs.Attr{}, err
		}
	}
	return object, attr, nil
}

func (h *Handler) parent(ctx context.Context, request facetfs.Request, segments []string) (facetfs.ObjectRef, string, error) {
	if len(segments) == 0 {
		return facetfs.ObjectRef{}, "", facetfs.ErrInvalid
	}
	parent, _, err := h.resolve(ctx, request, segments[:len(segments)-1])
	return parent, segments[len(segments)-1], err
}

func (h *Handler) options(w http.ResponseWriter) {
	w.Header().Set("DAV", "1")
	w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, COPY, MOVE")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch facetfs.CodeOf(err) {
	case facetfs.ErrAuthenticationRequired:
		status = http.StatusUnauthorized
	case facetfs.ErrAccessDenied, facetfs.ErrReadOnly:
		status = http.StatusForbidden
	case facetfs.ErrNotFound, facetfs.ErrStaleObject:
		status = http.StatusNotFound
	case facetfs.ErrExists, facetfs.ErrNotEmpty, facetfs.ErrBusy, facetfs.ErrStaleCursor:
		status = http.StatusConflict
	case facetfs.ErrInvalid, facetfs.ErrNameTooLong, facetfs.ErrNotDirectory, facetfs.ErrIsDirectory:
		status = http.StatusBadRequest
	case facetfs.ErrLockConflict, facetfs.ErrWouldBlock:
		status = http.StatusLocked
	case facetfs.ErrNoSpace, facetfs.ErrQuota:
		status = http.StatusInsufficientStorage
	case facetfs.ErrTooManyOpenFiles:
		status = http.StatusServiceUnavailable
	case facetfs.ErrNotSupported:
		status = http.StatusNotImplemented
	case facetfs.ErrCrossDevice:
		status = http.StatusBadGateway
	case facetfs.ErrCanceled:
		return
	case facetfs.ErrTimeout:
		status = http.StatusGatewayTimeout
	case facetfs.ErrIO, facetfs.ErrCorrupt:
		status = http.StatusInternalServerError
	}
	http.Error(w, http.StatusText(status), status)
}

func destinationURL(r *http.Request) (*url.URL, error) {
	destination := r.Header.Get("Destination")
	if destination == "" {
		return nil, facetfs.ErrInvalid
	}
	u, err := url.Parse(destination)
	if err != nil || u.User != nil || u.Fragment != "" {
		return nil, facetfs.ErrInvalid
	}
	if u.IsAbs() && u.Scheme != "http" && u.Scheme != "https" {
		return nil, facetfs.ErrCrossDevice
	}
	if u.IsAbs() && !strings.EqualFold(u.Host, r.Host) {
		return nil, facetfs.ErrCrossDevice
	}
	return u, nil
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }
