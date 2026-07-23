package webdav

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"slices"

	"github.com/sirrobot01/facetfs"
)

type copyEntry struct {
	segments []string
	object   facetfs.ObjectRef
	attr     facetfs.Attr
	parent   facetfs.ObjectRef
	name     string
}

func (h *Handler) copy(w http.ResponseWriter, r *http.Request, request facetfs.Request, source []string) {
	if len(source) == 0 {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	destination, err := destinationURL(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	target, err := h.segments(destination)
	if err != nil || len(target) == 0 {
		if err == nil {
			err = facetfs.ErrInvalid
		}
		h.writeError(w, err)
		return
	}
	if slices.Equal(target, source) || len(target) > len(source) && slices.Equal(target[:len(source)], source) {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	depth := r.Header.Get("Depth")
	if depth != "" && depth != "0" && depth != "infinity" {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	sourceObject, sourceAttr, err := h.resolve(r.Context(), request, source)
	if err != nil {
		h.writeError(w, err)
		return
	}
	entries := []copyEntry{{object: sourceObject, attr: sourceAttr}}
	if sourceAttr.Type == facetfs.NodeTypeDirectory && depth != "0" {
		if err := h.collect(r, request, sourceObject, nil, &entries); err != nil {
			h.writeError(w, err)
			return
		}
	}
	targetParent, targetName, err := h.parent(r.Context(), request, target)
	if err != nil {
		h.writeError(w, err)
		return
	}
	targetObject, targetAttr, lookupErr := h.server.Lookup(r.Context(), request, targetParent, targetName)
	exists := lookupErr == nil
	if lookupErr != nil && !errors.Is(lookupErr, facetfs.ErrNotFound) {
		h.writeError(w, lookupErr)
		return
	}
	if exists && r.Header.Get("Overwrite") == "F" {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	if exists {
		if err := h.removeObject(r, request, targetParent, targetName, targetObject, targetAttr); err != nil {
			h.writeError(w, err)
			return
		}
	}
	for _, entry := range entries {
		destinationSegments := append(slices.Clone(target), entry.segments...)
		if err := h.copyEntry(r, request, entry, destinationSegments); err != nil {
			h.writeError(w, err)
			return
		}
	}
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (h *Handler) collect(r *http.Request, request facetfs.Request, dir facetfs.ObjectRef, relative []string, entries *[]copyEntry) error {
	var cursor facetfs.DirCursor
	for {
		page, err := h.server.ReadDir(r.Context(), request, dir, cursor, 256)
		if err != nil {
			return err
		}
		for _, child := range page.Entries {
			if len(*entries) >= h.maxWalkNodes {
				return facetfs.ErrNoSpace
			}
			segments := append(slices.Clone(relative), child.Name)
			*entries = append(*entries, copyEntry{
				segments: segments, object: child.Object, attr: child.Attr, parent: dir, name: child.Name,
			})
			if child.Attr.Type == facetfs.NodeTypeDirectory {
				if err := h.collect(r, request, child.Object, segments, entries); err != nil {
					return err
				}
			}
		}
		if page.Next == "" {
			return nil
		}
		cursor = page.Next
	}
}

func (h *Handler) copyEntry(r *http.Request, request facetfs.Request, entry copyEntry, destination []string) error {
	parent, name, err := h.parent(r.Context(), request, destination)
	if err != nil {
		return err
	}
	mode := entry.attr.Mode
	switch entry.attr.Type {
	case facetfs.NodeTypeDirectory:
		_, _, err = h.server.Mkdir(r.Context(), request, parent, name, facetfs.SetAttr{Mode: &mode})
		return err
	case facetfs.NodeTypeSymlink:
		target, err := h.server.Readlink(r.Context(), request, entry.object)
		if err != nil {
			return err
		}
		_, _, err = h.server.Symlink(r.Context(), request, parent, name, target, facetfs.SetAttr{})
		return err
	case facetfs.NodeTypeRegular:
		return h.copyFile(r, request, entry, parent, name, mode)
	default:
		return facetfs.ErrNotSupported
	}
}

func (h *Handler) copyFile(r *http.Request, request facetfs.Request, entry copyEntry, parent facetfs.ObjectRef, name string, mode fs.FileMode) error {
	source, err := h.server.Open(r.Context(), request, entry.object, facetfs.OpenOptions{Access: facetfs.OpenRead, Share: allShares})
	if err != nil {
		return err
	}
	defer source.Close(r.Context())
	_, destination, _, err := h.server.Create(r.Context(), request, parent, name, facetfs.CreateOptions{
		Exclusive: true,
		Open:      facetfs.OpenOptions{Access: facetfs.OpenWrite, Share: allShares},
		Attr:      facetfs.SetAttr{Mode: &mode},
	})
	if err != nil {
		return err
	}
	defer destination.Close(r.Context())
	writable, ok := destination.(facetfs.MutableHandle)
	if !ok {
		return facetfs.ErrNotSupported
	}
	buf := make([]byte, 64<<10)
	for offset := int64(0); offset < entry.attr.Size; {
		n, readErr := source.ReadAt(r.Context(), buf, offset)
		if n > 0 {
			written, writeErr := writable.WriteAt(r.Context(), buf[:n], offset)
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return facetfs.ErrIO
			}
			offset += int64(n)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && offset == entry.attr.Size {
				break
			}
			return readErr
		}
	}
	_, err = writable.SetAttr(r.Context(), facetfs.SetAttr{ModifiedAt: &entry.attr.ModifiedAt})
	return err
}

func (h *Handler) removeObject(r *http.Request, request facetfs.Request, parent facetfs.ObjectRef, name string, object facetfs.ObjectRef, attr facetfs.Attr) error {
	if attr.Type == facetfs.NodeTypeDirectory {
		entries := []copyEntry{{object: object, attr: attr}}
		if err := h.collect(r, request, object, nil, &entries); err != nil {
			return err
		}
		for i := len(entries) - 1; i > 0; i-- {
			entry := entries[i]
			kind := facetfs.RemoveFile
			if entry.attr.Type == facetfs.NodeTypeDirectory {
				kind = facetfs.RemoveDirectory
			}
			if err := h.server.Remove(r.Context(), request, entry.parent, entry.name, kind); err != nil {
				return err
			}
		}
	}
	kind := facetfs.RemoveFile
	if attr.Type == facetfs.NodeTypeDirectory {
		kind = facetfs.RemoveDirectory
	}
	return h.server.Remove(r.Context(), request, parent, name, kind)
}
