package webdav

import (
	"errors"
	"net/http"
	"slices"

	"github.com/sirrobot01/facetfs"
)

func (h *Handler) move(w http.ResponseWriter, r *http.Request, request facetfs.Request, source []string) {
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
	if slices.Equal(source, target) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(target) > len(source) && slices.Equal(target[:len(source)], source) {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	sourceParent, sourceName, err := h.parent(r.Context(), request, source)
	if err != nil {
		h.writeError(w, err)
		return
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
	overwrite := r.Header.Get("Overwrite") != "F"
	if exists && !overwrite {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	// A MOVE changes both ends — the source leaves its collection and the
	// destination is written — so the If header is evaluated against each.
	sourceObject, sourceAttr, err := h.server.Lookup(r.Context(), request, sourceParent, sourceName)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if !h.checkIf(w, r, source, entityTag(sourceObject, sourceAttr), sourceObject, sourceParent) {
		return
	}
	if !h.checkIf(w, r, target, destinationTag(exists, targetObject, targetAttr), destinationLocks(exists, targetObject, targetParent)...) {
		return
	}
	if exists {
		if err := h.removeObject(r, request, targetParent, targetName, targetObject, targetAttr); err != nil {
			h.writeError(w, err)
			return
		}
	}
	if err := h.server.Rename(r.Context(), request, sourceParent, sourceName, targetParent, targetName, facetfs.RenameOptions{}); err != nil {
		h.writeError(w, err)
		return
	}
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}
