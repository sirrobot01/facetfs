package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := stdout.String(); got != "facetfsd dev\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestRunRequiresImplementedProfile(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	err := run(nil, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "no serving profile") {
		t.Fatalf("run() error = %v", err)
	}
}
