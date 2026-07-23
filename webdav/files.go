package webdav

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirrobot01/facetfs"
)

const allShares = facetfs.ShareRead | facetfs.ShareWrite | facetfs.ShareDelete

func (h *Handler) get(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	object, attr, err := h.resolve(r.Context(), request, segments)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if attr.Type == facetfs.NodeTypeDirectory {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	etag := entityTag(object, attr)
	if !readConditions(w, r, etag, attr.ModifiedAt) {
		return
	}
	handle, err := h.server.Open(r.Context(), request, object, facetfs.OpenOptions{Access: facetfs.OpenRead, Share: allShares})
	if err != nil {
		h.writeError(w, err)
		return
	}
	defer handle.Close(r.Context())

	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" && !ifRangeMatches(r.Header.Get("If-Range"), etag, attr.ModifiedAt) {
		rangeHeader = ""
	}
	offset, length, partial, err := byteRange(rangeHeader, attr.Size)
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", attr.Size))
		http.Error(w, http.StatusText(http.StatusRequestedRangeNotSatisfiable), http.StatusRequestedRangeNotSatisfiable)
		return
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", attr.ModifiedAt.UTC().Format(http.TimeFormat))
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, attr.Size))
		w.WriteHeader(http.StatusPartialContent)
	}
	if r.Method == http.MethodHead || length == 0 {
		return
	}
	buf := make([]byte, min(int64(64<<10), length))
	for written := int64(0); written < length; {
		chunk := min(int64(len(buf)), length-written)
		n, readErr := handle.ReadAt(r.Context(), buf[:chunk], offset+written)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			written += int64(n)
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return
			}
			break
		}
	}
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	parent, name, err := h.parent(r.Context(), request, segments)
	if err != nil {
		h.writeError(w, err)
		return
	}
	object, attr, lookupErr := h.server.Lookup(r.Context(), request, parent, name)
	exists := lookupErr == nil
	if lookupErr != nil && !errors.Is(lookupErr, facetfs.ErrNotFound) {
		h.writeError(w, lookupErr)
		return
	}
	etag := ""
	if exists {
		if attr.Type == facetfs.NodeTypeDirectory {
			h.writeError(w, facetfs.ErrIsDirectory)
			return
		}
		etag = entityTag(object, attr)
	}
	if !writeConditions(w, r, exists, etag) {
		return
	}

	var handle facetfs.Handle
	if exists {
		handle, err = h.server.Open(r.Context(), request, object, facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: allShares})
	} else {
		object, handle, _, err = h.server.Create(r.Context(), request, parent, name, facetfs.CreateOptions{
			Exclusive: true,
			Open:      facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: allShares},
		})
	}
	if err != nil {
		h.writeError(w, err)
		return
	}
	defer handle.Close(r.Context())
	mutable, ok := handle.(facetfs.MutableHandle)
	if !ok {
		h.writeError(w, facetfs.ErrNotSupported)
		return
	}
	body := http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	buf := make([]byte, 64<<10)
	var offset int64
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			written, writeErr := mutable.WriteAt(r.Context(), buf[:n], offset)
			offset += int64(written)
			if writeErr != nil {
				h.writeError(w, writeErr)
				return
			}
			if written != n {
				h.writeError(w, facetfs.ErrIO)
				return
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				var maxBytesError *http.MaxBytesError
				if errors.As(readErr, &maxBytesError) {
					http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
					return
				}
				h.writeError(w, facetfs.ErrInvalid)
				return
			}
			break
		}
	}
	attr, err = mutable.SetAttr(r.Context(), facetfs.SetAttr{Size: &offset})
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := mutable.Flush(r.Context(), true); err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("ETag", entityTag(object, attr))
	w.Header().Set("Last-Modified", attr.ModifiedAt.UTC().Format(http.TimeFormat))
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (h *Handler) mkcol(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	if r.ContentLength != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	parent, name, err := h.parent(r.Context(), request, segments)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if _, _, err := h.server.Mkdir(r.Context(), request, parent, name, facetfs.SetAttr{}); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	parent, name, err := h.parent(r.Context(), request, segments)
	if err != nil {
		h.writeError(w, err)
		return
	}
	object, attr, err := h.server.Lookup(r.Context(), request, parent, name)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := h.removeObject(r, request, parent, name, object, attr); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func entityTag(object facetfs.ObjectRef, attr facetfs.Attr) string {
	value := fmt.Sprintf("%s\x00%d\x00%s\x00%d", object.NodeID, object.Generation, attr.ChangeToken, attr.Size)
	return fmt.Sprintf("\"%x\"", sha256.Sum256([]byte(value)))
}

func readConditions(w http.ResponseWriter, r *http.Request, etag string, modified time.Time) bool {
	if value := r.Header.Get("If-Match"); value != "" && !strongETagMatches(value, etag) {
		w.WriteHeader(http.StatusPreconditionFailed)
		return false
	}
	if value := r.Header.Get("If-None-Match"); value != "" && weakETagMatches(value, etag) {
		w.WriteHeader(http.StatusNotModified)
		return false
	}
	if value := r.Header.Get("If-Modified-Since"); value != "" && r.Header.Get("If-None-Match") == "" {
		if since, err := http.ParseTime(value); err == nil && !modified.Truncate(time.Second).After(since) {
			w.WriteHeader(http.StatusNotModified)
			return false
		}
	}
	return true
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

func ifRangeMatches(value, etag string, modified time.Time) bool {
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "\"") {
		return value == etag
	}
	date, err := http.ParseTime(value)
	return err == nil && !modified.Truncate(time.Second).After(date)
}

func byteRange(header string, size int64) (int64, int64, bool, error) {
	if header == "" {
		return 0, size, false, nil
	}
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") || size == 0 {
		return 0, 0, false, facetfs.ErrInvalid
	}
	parts := strings.SplitN(strings.TrimPrefix(header, "bytes="), "-", 2)
	if len(parts) != 2 {
		return 0, 0, false, facetfs.ErrInvalid
	}
	if parts[0] == "" {
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, false, facetfs.ErrInvalid
		}
		if suffix > size {
			suffix = size
		}
		return size - suffix, suffix, true, nil
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, false, facetfs.ErrInvalid
	}
	end := size - 1
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil || end < start {
			return 0, 0, false, facetfs.ErrInvalid
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end - start + 1, true, nil
}
