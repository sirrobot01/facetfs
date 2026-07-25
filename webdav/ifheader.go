package webdav

import (
	"slices"
	"strings"
)

// ifCondition is a single term of a WebDAV If header list: either a state token
// (<...>) or an entity tag ([...]), optionally negated by "Not".
type ifCondition struct {
	not     bool
	isToken bool
	value   string
}

// ifList is one parenthesized list of conditions, optionally preceded by a
// resource tag identifying which resource the list applies to.
type ifList struct {
	resource   string
	conditions []ifCondition
}

// parseIfHeader parses an RFC 4918 §10.4 If header. It returns the lists and
// whether the header was present and well-formed.
func parseIfHeader(header string) ([]ifList, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, false
	}
	var lists []ifList
	resource := ""
	for i := 0; i < len(header); {
		switch header[i] {
		case ' ', '\t':
			i++
		case '<':
			end := strings.IndexByte(header[i:], '>')
			if end < 0 {
				return nil, false
			}
			resource = header[i+1 : i+end]
			i += end + 1
		case '(':
			conditions, next, ok := parseIfList(header, i+1)
			if !ok {
				return nil, false
			}
			lists = append(lists, ifList{resource: resource, conditions: conditions})
			i = next
		default:
			return nil, false
		}
	}
	if len(lists) == 0 {
		return nil, false
	}
	return lists, true
}

func parseIfList(header string, i int) ([]ifCondition, int, bool) {
	var conditions []ifCondition
	not := false
	for i < len(header) {
		switch header[i] {
		case ' ', '\t':
			i++
		case ')':
			return conditions, i + 1, true
		case '<':
			end := strings.IndexByte(header[i:], '>')
			if end < 0 {
				return nil, 0, false
			}
			conditions = append(conditions, ifCondition{not: not, isToken: true, value: header[i+1 : i+end]})
			not = false
			i += end + 1
		case '[':
			end := strings.IndexByte(header[i:], ']')
			if end < 0 {
				return nil, 0, false
			}
			conditions = append(conditions, ifCondition{not: not, value: header[i+1 : i+end]})
			not = false
			i += end + 1
		default:
			word, next := scanWord(header, i)
			if !strings.EqualFold(word, "Not") {
				return nil, 0, false
			}
			not = true
			i = next
		}
	}
	return nil, 0, false
}

func scanWord(header string, i int) (string, int) {
	start := i
	for i < len(header) && header[i] != ' ' && header[i] != '\t' && header[i] != '(' && header[i] != ')' && header[i] != '<' && header[i] != '[' {
		i++
	}
	return header[start:i], i
}

// ifTokens returns every state token positively asserted by an If header. These
// are the lock tokens the client submits to authorize a mutation.
func ifTokens(header string) []string {
	lists, ok := parseIfHeader(header)
	if !ok {
		return nil
	}
	var tokens []string
	for _, list := range lists {
		for _, condition := range list.conditions {
			if condition.isToken && !condition.not && condition.value != "" {
				tokens = append(tokens, condition.value)
			}
		}
	}
	return tokens
}

// firstIfToken returns the first positively asserted state token, used by LOCK
// refresh and other single-token operations.
func firstIfToken(header string) string {
	tokens := ifTokens(header)
	if len(tokens) == 0 {
		return ""
	}
	return tokens[0]
}

// ifTarget is the resource an If header is evaluated against: the path a tagged
// list must name to apply, and the entity tag and lock tokens its conditions are
// matched against. requestURI marks the resource the request itself names, as
// opposed to a second resource the method also touches, such as a COPY or MOVE
// destination.
type ifTarget struct {
	segments   []string
	requestURI bool
	etag       string
	tokens     []string
}

// evaluateIf reports whether an If header's preconditions are satisfied for
// target. A list applies when it is untagged — the No-tag-list production of RFC
// 4918 §10.4.2, which names the request-URI — or when its resource tag names
// target; resolve maps a tag to path segments. The header holds when any
// applicable list holds. A header composed entirely of lists tagged for other
// resources, such as tokens submitted for a MOVE destination, applies to nothing
// here and so cannot fail the request.
func evaluateIf(header string, target ifTarget, resolve func(string) ([]string, bool)) (ok bool) {
	lists, present := parseIfHeader(header)
	if !present {
		return true
	}
	applicable := false
	for _, list := range lists {
		if !listApplies(list, target, resolve) {
			continue
		}
		applicable = true
		if matchIfList(list.conditions, target.etag, target.tokens) {
			return true
		}
	}
	return !applicable
}

func listApplies(list ifList, target ifTarget, resolve func(string) ([]string, bool)) bool {
	if list.resource == "" {
		// The No-tag-list production names the request-URI (RFC 4918 §10.4.2), so an
		// untagged list governs a COPY or MOVE destination only when the destination
		// is itself the request-URI. Governing the destination otherwise requires a
		// list tagged with it.
		return target.requestURI
	}
	segments, ok := resolve(list.resource)
	return ok && slices.Equal(segments, target.segments)
}

func matchIfList(conditions []ifCondition, etag string, heldTokens []string) bool {
	for _, condition := range conditions {
		var satisfied bool
		if condition.isToken {
			satisfied = slices.Contains(heldTokens, condition.value)
		} else {
			satisfied = etagEqual(condition.value, etag)
		}
		if satisfied == condition.not {
			return false
		}
	}
	return true
}

func etagEqual(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// codedURL extracts the token from a Lock-Token header value of the form
// "<token>".
func codedURL(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < 2 || header[0] != '<' || header[len(header)-1] != '>' {
		return ""
	}
	return header[1 : len(header)-1]
}
