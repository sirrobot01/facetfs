package osfs

import (
	"encoding/json"

	"github.com/sirrobot01/facetfs"
)

type cursorState struct {
	Revision uint64 `json:"r"`
	Name     string `json:"n"`
}

func (f *FS) cursor(revision uint64, name string) facetfs.DirCursor {
	b, _ := json.Marshal(cursorState{Revision: revision, Name: name})
	return facetfs.DirCursor(f.cursors.Seal(b))
}

func (f *FS) parseCursor(cursor facetfs.DirCursor) (uint64, string, bool) {
	b, ok := f.cursors.Open(string(cursor))
	if !ok {
		return 0, "", false
	}
	var state cursorState
	if json.Unmarshal(b, &state) != nil {
		return 0, "", false
	}
	return state.Revision, state.Name, true
}
