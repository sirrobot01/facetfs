package webdav

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirrobot01/facetfs"
)

const (
	maxLockBody = 1 << 16
	// infiniteTimeout is the duration requested for a Timeout of "Infinite"; the
	// coordinator clamps it to its own maximum lock lifetime.
	infiniteTimeout = time.Hour
)

// lockInfo is the body of a LOCK request that creates a new lock (RFC 4918 §9.10).
type lockInfo struct {
	XMLName   xml.Name  `xml:"DAV: lockinfo"`
	LockScope lockScope `xml:"lockscope"`
	LockType  lockType  `xml:"locktype"`
	Owner     ownerElem `xml:"owner"`
}

type lockScope struct {
	Exclusive *struct{} `xml:"exclusive,omitempty"`
	Shared    *struct{} `xml:"shared,omitempty"`
}

type lockType struct {
	Write *struct{} `xml:"write,omitempty"`
}

type ownerElem struct {
	InnerXML string `xml:",innerxml"`
}

// lockResponse is the prop/lockdiscovery body returned by LOCK.
type lockResponse struct {
	XMLName       xml.Name          `xml:"DAV: prop"`
	LockDiscovery lockDiscoveryElem `xml:"lockdiscovery"`
}

type lockDiscoveryElem struct {
	ActiveLock activeLockElem `xml:"activelock"`
}

type activeLockElem struct {
	LockScope lockScope  `xml:"lockscope"`
	LockType  lockType   `xml:"locktype"`
	Depth     string     `xml:"depth"`
	Owner     *ownerElem `xml:"owner,omitempty"`
	Timeout   string     `xml:"timeout"`
	LockToken hrefElem   `xml:"locktoken"`
	LockRoot  hrefElem   `xml:"lockroot"`
}

type hrefElem struct {
	Href string `xml:"href"`
}

func (h *Handler) lock(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLockBody+1))
	if err != nil {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	if len(body) > maxLockBody {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		h.refreshLock(w, r, request, segments)
		return
	}

	var info lockInfo
	if xml.Unmarshal(body, &info) != nil || info.LockType.Write == nil {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	if info.LockScope.Exclusive == nil {
		// Only exclusive write locks are advertised in the supported-lock set.
		h.writeError(w, facetfs.ErrNotSupported)
		return
	}
	deep, ok := lockDepth(r.Header.Get("Depth"))
	if !ok {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}

	object, _, err := h.resolve(r.Context(), request, segments)
	created := false
	if facetfs.CodeOf(err) == facetfs.ErrNotFound {
		// RFC 4918 §7.3: create an empty locked resource rather than a lock-null.
		object, err = h.createEmpty(r, request, segments)
		created = true
	}
	if err != nil {
		h.writeError(w, err)
		return
	}

	held, err := h.server.AcquireLock(r.Context(), request, object, facetfs.DocumentLockRequest{
		Exclusive: true,
		Deep:      deep,
		Duration:  parseTimeout(r.Header.Get("Timeout")),
		Owner:     strings.TrimSpace(info.Owner.InnerXML),
	})
	if err != nil {
		if created {
			// The placeholder exists only to carry the lock. A LOCK that fails must
			// not leave a resource the client never asked to create.
			h.discardEmpty(r, request, segments)
		}
		h.writeError(w, err)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	h.writeLock(w, held, segments, deep, status)
}

func (h *Handler) refreshLock(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	token := firstIfToken(r.Header.Get("If"))
	if token == "" {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	object, _, err := h.resolve(r.Context(), request, segments)
	if err != nil {
		h.writeError(w, err)
		return
	}
	held, err := h.server.RefreshLock(r.Context(), request, object, token, parseTimeout(r.Header.Get("Timeout")))
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeLock(w, held, segments, held.Deep, http.StatusOK)
}

func (h *Handler) unlock(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	token := codedURL(r.Header.Get("Lock-Token"))
	if token == "" {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	object, _, err := h.resolve(r.Context(), request, segments)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := h.server.ReleaseLock(r.Context(), request, object, token); err != nil {
		// A token that does not match a lock on this resource is a conflict.
		if facetfs.CodeOf(err) == facetfs.ErrInvalid {
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) createEmpty(r *http.Request, request facetfs.Request, segments []string) (facetfs.ObjectRef, error) {
	parent, name, err := h.parent(r.Context(), request, segments)
	if err != nil {
		return facetfs.ObjectRef{}, err
	}
	object, handle, _, err := h.server.Create(r.Context(), request, parent, name, facetfs.CreateOptions{
		Exclusive: true,
		Open:      facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: allShares},
	})
	if err != nil {
		return facetfs.ObjectRef{}, err
	}
	_ = handle.Close(r.Context())
	return object, nil
}

// discardEmpty removes the placeholder created by createEmpty when the lock it
// was created for could not be acquired. Cleanup runs on an uncancelable context
// so that a client disconnecting mid-LOCK still leaves nothing behind, and its
// failure is not reported: the client is already receiving the acquire error.
func (h *Handler) discardEmpty(r *http.Request, request facetfs.Request, segments []string) {
	ctx := context.WithoutCancel(r.Context())
	parent, name, err := h.parent(ctx, request, segments)
	if err != nil {
		return
	}
	_ = h.server.Remove(ctx, request, parent, name, facetfs.RemoveFile)
}

func (h *Handler) writeLock(w http.ResponseWriter, lock facetfs.DocumentLock, segments []string, deep bool, status int) {
	depth := "0"
	if deep {
		depth = "infinity"
	}
	response := lockResponse{LockDiscovery: lockDiscoveryElem{ActiveLock: activeLockElem{
		LockScope: lockScope{Exclusive: &struct{}{}},
		LockType:  lockType{Write: &struct{}{}},
		Depth:     depth,
		Timeout:   formatTimeout(lock.Expires, h.server.Now()),
		LockToken: hrefElem{Href: lock.Token},
		LockRoot:  hrefElem{Href: h.href(segments, false)},
	}}}
	if lock.Owner != "" {
		response.LockDiscovery.ActiveLock.Owner = &ownerElem{InnerXML: lock.Owner}
	}
	var output bytes.Buffer
	output.WriteString(xml.Header)
	if err := xml.NewEncoder(&output).Encode(response); err != nil {
		h.writeError(w, facetfs.ErrIO)
		return
	}
	w.Header().Set("Lock-Token", "<"+lock.Token+">")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}

// lockDepth interprets the Depth header for LOCK. Only Depth 0 is granted: the
// coordinator resolves a lock against a single object, so a Depth infinity lock
// would report protection over the members of a collection that is not actually
// enforced. An explicit "infinity" is refused rather than silently downgraded,
// and an omitted header — which RFC 4918 §9.10.3 defaults to infinity — is
// granted as Depth 0 and reported as such in the lockdiscovery response.
func lockDepth(header string) (deep, ok bool) {
	switch header {
	case "", "0":
		return false, true
	default:
		return false, false
	}
}

func parseTimeout(header string) time.Duration {
	for field := range strings.SplitSeq(header, ",") {
		field = strings.TrimSpace(field)
		if strings.EqualFold(field, "Infinite") {
			return infiniteTimeout
		}
		if seconds, ok := strings.CutPrefix(field, "Second-"); ok {
			if value, err := strconv.Atoi(seconds); err == nil && value > 0 {
				return time.Duration(value) * time.Second
			}
		}
	}
	return 0
}

func formatTimeout(expires, now time.Time) string {
	seconds := int(expires.Sub(now).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return "Second-" + strconv.Itoa(seconds)
}
