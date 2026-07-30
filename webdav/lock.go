package webdav

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	maxLockBody = 1 << 16
	// infiniteTimeout is the duration requested for a Timeout of "Infinite";
	// the lock system clamps it to its own maximum lock lifetime.
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

func (h *Handler) lock(w http.ResponseWriter, r *http.Request, segments []string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLockBody+1))
	if err != nil {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	if len(body) > maxLockBody {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		h.refreshLock(w, r, segments)
		return
	}

	var info lockInfo
	if xml.Unmarshal(body, &info) != nil || info.LockType.Write == nil {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	if info.LockScope.Exclusive == nil {
		// Only exclusive write locks are advertised in the supported-lock set.
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}
	if _, ok := lockDepth(r.Header.Get("Depth")); !ok {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}

	p := fsPath(segments)
	_, err = h.FileSystem.Stat(r.Context(), p)
	created := false
	if errors.Is(err, fs.ErrNotExist) {
		// RFC 4918 §7.3: create an empty locked resource rather than a lock-null.
		// Creating it adds a member, so a lock on the parent governs it.
		if len(segments) == 0 {
			h.writeError(w, r, fs.ErrInvalid)
			return
		}
		if !h.checkIf(w, r, segments, "", fsPath(segments[:len(segments)-1])) {
			return
		}
		err = h.createEmpty(r, p)
		created = true
	}
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	held, err := h.LockSystem.Create(h.now(), LockDetails{
		Root:     p,
		Owner:    strings.TrimSpace(info.Owner.InnerXML),
		Duration: parseTimeout(r.Header.Get("Timeout")),
	})
	if err != nil {
		if created {
			// The placeholder exists only to carry the lock. A LOCK that fails must
			// not leave a resource the client never asked to create.
			h.discardEmpty(r, p)
		}
		h.writeError(w, r, err)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	h.writeLock(w, held, segments, status)
}

func (h *Handler) refreshLock(w http.ResponseWriter, r *http.Request, segments []string) {
	token := firstIfToken(r.Header.Get("If"))
	if token == "" {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	p := fsPath(segments)
	if _, err := h.FileSystem.Stat(r.Context(), p); err != nil {
		h.writeError(w, r, err)
		return
	}
	held, err := h.LockSystem.Refresh(h.now(), p, token, parseTimeout(r.Header.Get("Timeout")))
	if err != nil {
		if errors.Is(err, ErrNoSuchLock) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		h.writeError(w, r, err)
		return
	}
	h.writeLock(w, held, segments, http.StatusOK)
}

func (h *Handler) unlock(w http.ResponseWriter, r *http.Request, segments []string) {
	token := codedURL(r.Header.Get("Lock-Token"))
	if token == "" {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	p := fsPath(segments)
	if _, err := h.FileSystem.Stat(r.Context(), p); err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.LockSystem.Unlock(h.now(), p, token); err != nil {
		// A token that does not match a lock on this resource is a conflict.
		if errors.Is(err, ErrNoSuchLock) {
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) createEmpty(r *http.Request, p string) error {
	file, err := h.FileSystem.OpenFile(r.Context(), p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	return file.Close()
}

// discardEmpty removes the placeholder created by createEmpty when the lock it
// was created for could not be acquired. Cleanup runs on an uncancelable
// context so that a client disconnecting mid-LOCK still leaves nothing behind,
// and its failure is not reported: the client is already receiving the acquire
// error.
func (h *Handler) discardEmpty(r *http.Request, p string) {
	_ = h.FileSystem.RemoveAll(context.WithoutCancel(r.Context()), p)
}

func (h *Handler) writeLock(w http.ResponseWriter, lock LockDetails, segments []string, status int) {
	response := lockResponse{LockDiscovery: lockDiscoveryElem{ActiveLock: activeLockElem{
		LockScope: lockScope{Exclusive: &struct{}{}},
		LockType:  lockType{Write: &struct{}{}},
		Depth:     "0",
		Timeout:   formatTimeout(lock.Expires, h.now()),
		LockToken: hrefElem{Href: lock.Token},
		LockRoot:  hrefElem{Href: h.href(segments, false)},
	}}}
	if lock.Owner != "" {
		response.LockDiscovery.ActiveLock.Owner = &ownerElem{InnerXML: lock.Owner}
	}
	var output bytes.Buffer
	output.WriteString(xml.Header)
	if err := xml.NewEncoder(&output).Encode(response); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Lock-Token", "<"+lock.Token+">")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}

// lockDepth interprets the Depth header for LOCK. Only Depth 0 is granted: the
// lock system resolves a lock against a single path, so a Depth infinity lock
// would report protection over the members of a collection that is not
// actually enforced. An explicit "infinity" is refused rather than silently
// downgraded, and an omitted header — which RFC 4918 §9.10.3 defaults to
// infinity — is granted as Depth 0 and reported as such in the lockdiscovery
// response.
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
