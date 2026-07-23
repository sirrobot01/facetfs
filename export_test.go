package facetfs

import "testing"

func TestExportSupports(t *testing.T) {
	t.Parallel()

	all := Export{}
	if !all.Supports(ProtocolNFS4) || !all.Supports(ProtocolWebDAV) {
		t.Fatal("an empty protocol list should allow every frontend")
	}

	webOnly := Export{Protocols: []Protocol{ProtocolWebDAV}}
	if !webOnly.Supports(ProtocolWebDAV) {
		t.Fatal("configured protocol should be supported")
	}
	if webOnly.Supports(ProtocolSMB) {
		t.Fatal("unconfigured protocol should not be supported")
	}
}
