package facetfs

import "slices"

// Export binds a stable external identity to a backend root. An empty
// Protocols list makes the export visible to every enabled frontend.
type Export struct {
	ID        string
	Name      string
	Backend   Backend
	ReadOnly  bool
	Protocols []Protocol
}

type ExportInfo struct {
	ID           string
	Name         string
	ReadOnly     bool
	Protocols    []Protocol
	Capabilities Capabilities
}

// Supports reports whether this export is visible through protocol.
func (e Export) Supports(protocol Protocol) bool {
	if len(e.Protocols) == 0 {
		return true
	}
	return slices.Contains(e.Protocols, protocol)
}
