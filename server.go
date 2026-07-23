package facetfs

import (
	"context"
	"fmt"
	"regexp"
)

var exportIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Config contains the protocol-neutral server configuration.
type Config struct {
	Exports []Export
}

// Server is the shared FacetFS runtime. Protocol registration and serving will
// be added with the coordinator during Phase 1.
type Server struct {
	exports      []Export
	capabilities map[string]Capabilities
}

// New validates export identities and snapshots backend capabilities.
func New(ctx context.Context, config Config) (*Server, error) {
	if len(config.Exports) == 0 {
		return nil, fmt.Errorf("facetfs: at least one export is required")
	}

	exports := cloneExports(config.Exports)
	capabilities := make(map[string]Capabilities, len(exports))
	seen := make(map[string]struct{}, len(exports))
	for i := range exports {
		export := &exports[i]
		if !exportIDPattern.MatchString(export.ID) {
			return nil, fmt.Errorf("facetfs: export %d has invalid ID %q", i, export.ID)
		}
		if _, exists := seen[export.ID]; exists {
			return nil, fmt.Errorf("facetfs: duplicate export ID %q", export.ID)
		}
		seen[export.ID] = struct{}{}
		if export.Name == "" {
			return nil, fmt.Errorf("facetfs: export %q has an empty name", export.ID)
		}
		if export.Backend == nil {
			return nil, fmt.Errorf("facetfs: export %q has no backend", export.ID)
		}
		if err := validateProtocols(export.Protocols); err != nil {
			return nil, fmt.Errorf("facetfs: export %q: %w", export.ID, err)
		}
		caps, err := export.Backend.Capabilities(ctx)
		if err != nil {
			return nil, fmt.Errorf("facetfs: export %q capabilities: %w", export.ID, err)
		}
		if !caps.StableObjectIDs {
			return nil, fmt.Errorf("facetfs: export %q: stable object IDs are required", export.ID)
		}
		if !caps.ReadOnly {
			if _, ok := export.Backend.(MutableBackend); !ok {
				return nil, fmt.Errorf("facetfs: export %q: writable backend does not implement facetfs.MutableBackend", export.ID)
			}
		}
		if caps.ReadOnly {
			export.ReadOnly = true
		}
		capabilities[export.ID] = caps
	}

	return &Server{exports: exports, capabilities: capabilities}, nil
}

// Exports returns a copy of the configured exports.
func (s *Server) Exports() []Export {
	if s == nil {
		return nil
	}
	return cloneExports(s.exports)
}

func cloneExports(exports []Export) []Export {
	cloned := make([]Export, len(exports))
	copy(cloned, exports)
	for i := range cloned {
		cloned[i].Protocols = append([]Protocol(nil), exports[i].Protocols...)
	}
	return cloned
}

// Capabilities returns the startup capability snapshot for an export.
func (s *Server) Capabilities(exportID string) (Capabilities, bool) {
	if s == nil {
		return Capabilities{}, false
	}
	caps, ok := s.capabilities[exportID]
	return caps, ok
}

func validateProtocols(protocols []Protocol) error {
	seen := make(map[Protocol]struct{}, len(protocols))
	for _, protocol := range protocols {
		switch protocol {
		case ProtocolNFS4, ProtocolSMB, ProtocolSFTP, ProtocolWebDAV:
		default:
			return fmt.Errorf("unknown protocol %q", protocol)
		}
		if _, exists := seen[protocol]; exists {
			return fmt.Errorf("duplicate protocol %q", protocol)
		}
		seen[protocol] = struct{}{}
	}
	return nil
}
