package webdav

import (
	"bytes"
	"encoding/xml"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/sirrobot01/facetfs"
)

const maxPropfindBody = 1 << 20

type multistatus struct {
	XMLName   xml.Name       `xml:"DAV: multistatus"`
	Responses []propResponse `xml:"response"`
}

type propResponse struct {
	Href     string   `xml:"href"`
	Propstat propstat `xml:"propstat"`
}

type propstat struct {
	Prop   properties `xml:"prop"`
	Status string     `xml:"status"`
}

type properties struct {
	DisplayName   string       `xml:"displayname"`
	ResourceType  resourceType `xml:"resourcetype"`
	ContentLength string       `xml:"getcontentlength,omitempty"`
	LastModified  string       `xml:"getlastmodified,omitempty"`
	CreationDate  string       `xml:"creationdate,omitempty"`
	ETag          string       `xml:"getetag,omitempty"`
	ContentType   string       `xml:"getcontenttype,omitempty"`
}

type resourceType struct {
	Collection *struct{} `xml:"collection,omitempty"`
}

func (h *Handler) propfind(w http.ResponseWriter, r *http.Request, request facetfs.Request, segments []string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPropfindBody+1))
	if err != nil {
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	if len(body) > maxPropfindBody {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		var requestBody struct{ XMLName xml.Name }
		if xml.Unmarshal(body, &requestBody) != nil || requestBody.XMLName != (xml.Name{Space: "DAV:", Local: "propfind"}) {
			h.writeError(w, facetfs.ErrInvalid)
			return
		}
	}
	object, attr, err := h.resolve(r.Context(), request, segments)
	if err != nil {
		h.writeError(w, err)
		return
	}
	entries := []copyEntry{{object: object, attr: attr}}
	depth := r.Header.Get("Depth")
	switch depth {
	case "0":
	case "1":
		if attr.Type == facetfs.NodeTypeDirectory {
			if err := h.collectDepthOne(r, request, object, &entries); err != nil {
				h.writeError(w, err)
				return
			}
		}
	case "", "infinity":
		if attr.Type == facetfs.NodeTypeDirectory {
			if err := h.collect(r, request, object, nil, &entries); err != nil {
				h.writeError(w, err)
				return
			}
		}
	default:
		h.writeError(w, facetfs.ErrInvalid)
		return
	}
	status := multistatus{Responses: make([]propResponse, len(entries))}
	for i, entry := range entries {
		entrySegments := append(append([]string(nil), segments...), entry.segments...)
		status.Responses[i] = h.propertyResponse(entrySegments, entry.object, entry.attr)
	}
	var output bytes.Buffer
	output.WriteString(xml.Header)
	if err := xml.NewEncoder(&output).Encode(status); err != nil {
		h.writeError(w, facetfs.ErrIO)
		return
	}
	if int64(output.Len()) > h.maxResponseBytes {
		h.writeError(w, facetfs.ErrNoSpace)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = w.Write(output.Bytes())
}

func (h *Handler) collectDepthOne(r *http.Request, request facetfs.Request, dir facetfs.ObjectRef, entries *[]copyEntry) error {
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
			*entries = append(*entries, copyEntry{segments: []string{child.Name}, object: child.Object, attr: child.Attr})
		}
		if page.Next == "" {
			return nil
		}
		cursor = page.Next
	}
}

func (h *Handler) propertyResponse(segments []string, object facetfs.ObjectRef, attr facetfs.Attr) propResponse {
	displayName := h.exportID
	if len(segments) > 0 {
		displayName = segments[len(segments)-1]
	}
	properties := properties{
		DisplayName:  displayName,
		LastModified: attr.ModifiedAt.UTC().Format(http.TimeFormat),
		CreationDate: attr.CreatedAt.UTC().Format(time.RFC3339Nano),
		ETag:         entityTag(object, attr),
	}
	if attr.Type == facetfs.NodeTypeDirectory {
		properties.ResourceType.Collection = &struct{}{}
		properties.ContentType = "httpd/unix-directory"
	} else {
		properties.ContentLength = strconv.FormatInt(attr.Size, 10)
		properties.ContentType = mime.TypeByExtension(path.Ext(displayName))
		if properties.ContentType == "" {
			properties.ContentType = "application/octet-stream"
		}
	}
	return propResponse{
		Href:     h.href(segments, attr.Type == facetfs.NodeTypeDirectory),
		Propstat: propstat{Prop: properties, Status: "HTTP/1.1 200 OK"},
	}
}

func (h *Handler) href(segments []string, directory bool) string {
	parts := make([]string, len(segments))
	for i, segment := range segments {
		parts[i] = url.PathEscape(segment)
	}
	href := h.prefix
	if href == "/" {
		href = ""
	}
	if len(parts) > 0 {
		href += "/" + strings.Join(parts, "/")
	}
	if href == "" {
		href = "/"
	}
	if directory && !strings.HasSuffix(href, "/") {
		href += "/"
	}
	return href
}
