package webdav

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"

	"github.com/sirrobot01/facetfs"
)

// walkEntry is one resource visited by a traversal, with its path relative to
// the traversal root.
type walkEntry struct {
	segments []string
	fi       fs.FileInfo
}

// walkFS appends the entries under dir to entries. File info comes from
// Readdir, so a symbolic link is reported as itself, not its target. When
// recurse is false only the immediate members are visited.
func (h *Handler) walkFS(r *http.Request, dir string, relative []string, recurse bool, entries *[]walkEntry) error {
	file, err := h.FileSystem.OpenFile(r.Context(), dir, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	for {
		children, err := file.Readdir(256)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(children) == 0 {
			return nil
		}
		for _, child := range children {
			if len(*entries) >= h.maxWalkNodes() {
				return errWalkLimit
			}
			segments := append(slices.Clone(relative), child.Name())
			*entries = append(*entries, walkEntry{segments: segments, fi: child})
			if recurse && child.IsDir() {
				if err := h.walkFS(r, path.Join(dir, child.Name()), segments, true, entries); err != nil {
					return err
				}
			}
		}
	}
}

func (h *Handler) copy(w http.ResponseWriter, r *http.Request, source []string) {
	if len(source) == 0 {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	destination, err := destinationURL(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	target, err := h.segments(destination)
	if err != nil || len(target) == 0 {
		if err == nil {
			err = fs.ErrInvalid
		}
		h.writeError(w, r, err)
		return
	}
	if slices.Equal(target, source) || len(target) > len(source) && slices.Equal(target[:len(source)], source) {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	depth := r.Header.Get("Depth")
	if depth != "" && depth != "0" && depth != "infinity" {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	sourceInfo, err := h.FileSystem.Stat(r.Context(), fsPath(source))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	entries := []walkEntry{{fi: sourceInfo}}
	if sourceInfo.IsDir() && depth != "0" {
		if err := h.walkFS(r, fsPath(source), nil, true, &entries); err != nil {
			h.writeError(w, r, err)
			return
		}
	}
	targetPath := fsPath(target)
	targetInfo, statErr := h.FileSystem.Stat(r.Context(), targetPath)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		h.writeError(w, r, statErr)
		return
	}
	if !h.destinationParentExists(w, r, target) {
		return
	}
	if exists && r.Header.Get("Overwrite") == "F" {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	// A COPY writes only the destination; the source is read, not modified, so no
	// lock on it is required (RFC 4918 §9.8.3).
	if !h.checkIf(w, r, target, destinationTag(exists, targetInfo), destinationLocks(exists, target)...) {
		return
	}
	if exists {
		if err := h.FileSystem.RemoveAll(r.Context(), targetPath); err != nil {
			h.writeError(w, r, err)
			return
		}
	}
	for _, entry := range entries {
		entrySource := path.Join(fsPath(source), path.Join(entry.segments...))
		entryTarget := path.Join(targetPath, path.Join(entry.segments...))
		if err := h.copyEntry(r, entry, entrySource, entryTarget); err != nil {
			h.writeError(w, r, err)
			return
		}
	}
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (h *Handler) copyEntry(r *http.Request, entry walkEntry, source, destination string) error {
	switch {
	case entry.fi.IsDir():
		return h.FileSystem.Mkdir(r.Context(), destination, entry.fi.Mode().Perm())
	case entry.fi.Mode()&fs.ModeSymlink != 0:
		symlinks, ok := h.FileSystem.(facetfs.SymlinkFS)
		if !ok {
			return fs.ErrInvalid
		}
		target, err := symlinks.Readlink(r.Context(), source)
		if err != nil {
			return err
		}
		return symlinks.Symlink(r.Context(), target, destination)
	default:
		return h.copyFile(r, source, destination, entry.fi.Mode().Perm())
	}
}

func (h *Handler) copyFile(r *http.Request, source, destination string, perm fs.FileMode) error {
	from, err := h.FileSystem.OpenFile(r.Context(), source, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := h.FileSystem.OpenFile(r.Context(), destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(to, from)
	if closeErr := to.Close(); err == nil {
		err = closeErr
	}
	return err
}

// destinationParentExists checks that the collection a COPY or MOVE writes
// into is mapped, writing 409 when it is not (RFC 4918 §9.8.5, §9.9.4).
func (h *Handler) destinationParentExists(w http.ResponseWriter, r *http.Request, target []string) bool {
	fi, err := h.FileSystem.Stat(r.Context(), fsPath(target[:len(target)-1]))
	if err != nil || !fi.IsDir() {
		http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
		return false
	}
	return true
}

// destinationTag returns the entity tag a COPY or MOVE destination presents to
// an If header, which is empty when nothing is there to overwrite.
func destinationTag(exists bool, fi fs.FileInfo) string {
	if !exists {
		return ""
	}
	return entityTag(fi)
}

// destinationLocks returns the paths whose locks govern writing a COPY or MOVE
// destination: the collection it is written into, and the resource it
// replaces.
func destinationLocks(exists bool, target []string) []string {
	parent := fsPath(target[:len(target)-1])
	if !exists {
		return []string{parent}
	}
	return []string{parent, fsPath(target)}
}

func (h *Handler) move(w http.ResponseWriter, r *http.Request, source []string) {
	if len(source) == 0 {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	destination, err := destinationURL(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	target, err := h.segments(destination)
	if err != nil || len(target) == 0 {
		if err == nil {
			err = fs.ErrInvalid
		}
		h.writeError(w, r, err)
		return
	}
	if slices.Equal(source, target) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(target) > len(source) && slices.Equal(target[:len(source)], source) {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	sourcePath := fsPath(source)
	sourceInfo, err := h.FileSystem.Stat(r.Context(), sourcePath)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	targetPath := fsPath(target)
	targetInfo, statErr := h.FileSystem.Stat(r.Context(), targetPath)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		h.writeError(w, r, statErr)
		return
	}
	if !h.destinationParentExists(w, r, target) {
		return
	}
	if exists && r.Header.Get("Overwrite") == "F" {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	// A MOVE changes both ends — the source leaves its collection and the
	// destination is written — so the If header is evaluated against each.
	if !h.checkIf(w, r, source, entityTag(sourceInfo), sourcePath, fsPath(source[:len(source)-1])) {
		return
	}
	if !h.checkIf(w, r, target, destinationTag(exists, targetInfo), destinationLocks(exists, target)...) {
		return
	}
	if exists {
		if err := h.FileSystem.RemoveAll(r.Context(), targetPath); err != nil {
			h.writeError(w, r, err)
			return
		}
	}
	if err := h.FileSystem.Rename(r.Context(), sourcePath, targetPath); err != nil {
		h.writeError(w, r, err)
		return
	}
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}
