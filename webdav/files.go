package webdav

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
)

func (h *Handler) get(w http.ResponseWriter, r *http.Request, segments []string) {
	p := fsPath(segments)
	fi, err := h.FileSystem.Stat(r.Context(), p)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if fi.IsDir() {
		h.methodNotAllowed(w)
		return
	}
	file, err := h.FileSystem.OpenFile(r.Context(), p, os.O_RDONLY, 0)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	defer file.Close()
	w.Header().Set("ETag", entityTag(fi))
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), file)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 0 {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	p := fsPath(segments)
	parent := fsPath(segments[:len(segments)-1])
	fi, statErr := h.FileSystem.Stat(r.Context(), p)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		h.writeError(w, r, statErr)
		return
	}
	etag := ""
	if exists {
		if fi.IsDir() {
			h.writeError(w, r, fs.ErrInvalid)
			return
		}
		etag = entityTag(fi)
	}
	// A lock on the parent collection governs adding a member, so it is consulted
	// whether or not the target itself exists.
	governed := []string{parent}
	if exists {
		governed = append(governed, p)
	}
	if !h.checkIf(w, r, segments, etag, governed...) {
		return
	}
	if !writeConditions(w, r, exists, etag) {
		return
	}

	file, err := h.FileSystem.OpenFile(r.Context(), p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		if !exists && errors.Is(err, fs.ErrNotExist) {
			// RFC 4918 §9.7.1: a missing intermediate collection is 409.
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		h.writeError(w, r, err)
		return
	}
	_, err = io.Copy(file, http.MaxBytesReader(w, r.Body, h.maxBodyBytes()))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		h.writeError(w, r, err)
		return
	}
	if fi, err := h.FileSystem.Stat(r.Context(), p); err == nil {
		w.Header().Set("ETag", entityTag(fi))
		w.Header().Set("Last-Modified", fi.ModTime().UTC().Format(http.TimeFormat))
	}
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (h *Handler) mkcol(w http.ResponseWriter, r *http.Request, segments []string) {
	if r.ContentLength != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if len(segments) == 0 {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	// The collection does not exist yet, so only a lock on its parent governs it.
	if !h.checkIf(w, r, segments, "", fsPath(segments[:len(segments)-1])) {
		return
	}
	if err := h.FileSystem.Mkdir(r.Context(), fsPath(segments), 0o755); err != nil {
		switch {
		case errors.Is(err, fs.ErrExist):
			// RFC 4918 §9.3.1: MKCOL on a mapped URL is 405.
			h.methodNotAllowed(w)
		case errors.Is(err, fs.ErrNotExist):
			// A missing intermediate collection is 409.
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
		default:
			h.writeError(w, r, err)
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 0 {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	p := fsPath(segments)
	fi, err := h.FileSystem.Stat(r.Context(), p)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	// Removing a member is governed by a lock on the member or on its collection.
	if !h.checkIf(w, r, segments, entityTag(fi), p, fsPath(segments[:len(segments)-1])) {
		return
	}
	if err := h.FileSystem.RemoveAll(r.Context(), p); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// entityTag derives an entity tag from the file's modification time and size,
// like x/net/webdav. A FileSystem whose ModTime is too coarse for this to be
// strong should serve GET behind its own validator.
func entityTag(fi fs.FileInfo) string {
	return fmt.Sprintf("\"%x%x\"", fi.ModTime().UnixNano(), fi.Size())
}

// checkIf enforces the WebDAV locking preconditions for a mutation of the
// resource named by segments. It first evaluates the If header (RFC 4918
// §10.4), writing 412 when the header applies and fails, and then guards every
// governed path against live locks the request did not satisfy with a token,
// writing 423. A state token is satisfied by a lock held on any governed path,
// so a client mutating a member of a locked collection submits the
// collection's token (RFC 4918 §7.4). It returns false when the mutation must
// not proceed.
func (h *Handler) checkIf(w http.ResponseWriter, r *http.Request, segments []string, etag string, governed ...string) bool {
	header := r.Header.Get("If")
	tokens := ifTokens(header)
	now := h.now()
	if header != "" {
		var held []string
		if h.LockSystem != nil {
			for _, root := range governed {
				if lock, ok := h.LockSystem.Holder(now, root); ok {
					held = append(held, lock.Token)
				}
			}
		}
		// Untagged lists name the request-URI, so whether this resource is the one
		// the request names decides if they apply to it.
		requestSegments, err := h.segments(r.URL)
		target := ifTarget{
			segments:   segments,
			requestURI: err == nil && slices.Equal(requestSegments, segments),
			etag:       etag,
			tokens:     held,
		}
		if !evaluateIf(header, target, h.tagResolver(r)) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return false
		}
	}
	if h.LockSystem != nil {
		for _, root := range governed {
			if _, locked := h.LockSystem.Guard(now, root, tokens); locked {
				http.Error(w, http.StatusText(http.StatusLocked), http.StatusLocked)
				return false
			}
		}
	}
	return true
}

// tagResolver maps an If header resource tag to path segments so that a tagged
// list can be matched against the resource it names. A tag naming another
// host, or a path outside this prefix, resolves to nothing and so applies to
// no resource served here.
func (h *Handler) tagResolver(r *http.Request) func(string) ([]string, bool) {
	return func(tag string) ([]string, bool) {
		parsed, err := url.Parse(tag)
		if err != nil {
			return nil, false
		}
		if parsed.Host != "" && !strings.EqualFold(parsed.Host, r.Host) {
			return nil, false
		}
		segments, err := h.segments(parsed)
		if err != nil {
			return nil, false
		}
		return segments, true
	}
}

func writeConditions(w http.ResponseWriter, r *http.Request, exists bool, etag string) bool {
	if value := r.Header.Get("If-Match"); value != "" && (!exists || !strongETagMatches(value, etag)) {
		w.WriteHeader(http.StatusPreconditionFailed)
		return false
	}
	if value := r.Header.Get("If-None-Match"); value != "" && exists && weakETagMatches(value, etag) {
		w.WriteHeader(http.StatusPreconditionFailed)
		return false
	}
	return true
}

func strongETagMatches(header, etag string) bool {
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for value := range strings.SplitSeq(header, ",") {
		if strings.TrimSpace(value) == etag {
			return true
		}
	}
	return false
}

func weakETagMatches(header, etag string) bool {
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for value := range strings.SplitSeq(header, ",") {
		if strings.TrimPrefix(strings.TrimSpace(value), "W/") == etag {
			return true
		}
	}
	return false
}
