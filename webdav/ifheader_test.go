package webdav

import (
	"strings"
	"testing"
)

// resolveTestTag stands in for the handler's path resolution, mapping tags under
// one host and prefix to segments and rejecting everything else.
func resolveTestTag(tag string) ([]string, bool) {
	path, ok := strings.CutPrefix(tag, "http://example.com/dav/")
	if !ok {
		return nil, false
	}
	if path == "" {
		return nil, true
	}
	return strings.Split(path, "/"), true
}

func TestEvaluateIf(t *testing.T) {
	file := ifTarget{
		segments:   []string{"file"},
		requestURI: true,
		etag:       `"abc"`,
		tokens:     []string{"urn:uuid:held"},
	}
	// A COPY or MOVE destination is touched by the request but is not the resource
	// the request-URI names.
	destination := ifTarget{segments: []string{"dest"}, etag: `"def"`}

	cases := []struct {
		name   string
		header string
		target ifTarget
		want   bool
	}{
		{"absent header", "", file, true},
		{"unparseable header does not block", "garbage", file, true},
		{"untagged etag matches", `(["abc"])`, file, true},
		{"untagged etag differs", `(["zzz"])`, file, false},
		{"untagged token matches", `(<urn:uuid:held>)`, file, true},
		{"untagged token differs", `(<urn:uuid:other>)`, file, false},
		{"weak etag compares equal", `([W/"abc"])`, file, true},
		{"all conditions in a list must hold", `(["abc"] <urn:uuid:other>)`, file, false},
		{"any list may hold", `(["zzz"]) (["abc"])`, file, true},
		{"Not inverts a miss into a hold", `(Not <urn:uuid:other>)`, file, true},
		{"Not inverts a match into a failure", `(Not <urn:uuid:held>)`, file, false},

		// Tagged lists are evaluated against the resource they name.
		{"tagged for this resource holds", `<http://example.com/dav/file> (["abc"])`, file, true},
		{"tagged for this resource fails", `<http://example.com/dav/file> (["zzz"])`, file, false},
		{"tagged for another resource does not apply", `<http://example.com/dav/other> (["zzz"])`, file, true},
		{"tagged for another host does not apply", `<http://elsewhere.test/dav/file> (["zzz"])`, file, true},
		{"unresolvable tag does not apply", `<mailto:someone@example.com> (["zzz"])`, file, true},
		{"a matching untagged list rescues a failed foreign tag", `<http://example.com/dav/other> (["zzz"]) (["abc"])`, file, true},
		{"a list tagged for this resource still fails alongside a foreign one", `<http://example.com/dav/other> (["abc"]) <http://example.com/dav/file> (["zzz"])`, file, false},

		// Untagged lists name the request-URI, so they leave a destination alone.
		{"untagged list does not govern a destination", `(["abc"])`, destination, true},
		{"tagged list governs the destination it names", `<http://example.com/dav/dest> (["def"])`, destination, true},
		{"tagged list fails for the destination it names", `<http://example.com/dav/dest> (["zzz"])`, destination, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := evaluateIf(test.header, test.target, resolveTestTag); got != test.want {
				t.Errorf("evaluateIf(%q) = %v, want %v", test.header, got, test.want)
			}
		})
	}
}

func TestIfTokens(t *testing.T) {
	header := `<http://example.com/dav/a> (<urn:uuid:1> ["etag"]) (Not <urn:uuid:2>) (<urn:uuid:3>)`
	tokens := ifTokens(header)
	// Tokens are collected wherever they appear, since a token submitted anywhere
	// authorizes the mutation, but a negated token is not being asserted.
	want := []string{"urn:uuid:1", "urn:uuid:3"}
	if len(tokens) != len(want) {
		t.Fatalf("ifTokens = %v, want %v", tokens, want)
	}
	for i := range want {
		if tokens[i] != want[i] {
			t.Fatalf("ifTokens = %v, want %v", tokens, want)
		}
	}
	if got := ifTokens("garbage"); got != nil {
		t.Errorf("ifTokens(unparseable) = %v, want nil", got)
	}
}

func TestCodedURL(t *testing.T) {
	if got := codedURL("<urn:uuid:1>"); got != "urn:uuid:1" {
		t.Errorf("codedURL = %q", got)
	}
	for _, header := range []string{"", "urn:uuid:1", "<urn:uuid:1", "urn:uuid:1>", "<>"} {
		if got := codedURL(header); got != "" && header != "<>" {
			t.Errorf("codedURL(%q) = %q, want empty", header, got)
		}
	}
}
