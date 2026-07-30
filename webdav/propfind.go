package webdav

import (
	"bytes"
	"encoding/xml"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
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
	DisplayName   string        `xml:"displayname"`
	ResourceType  resourceType  `xml:"resourcetype"`
	ContentLength string        `xml:"getcontentlength,omitempty"`
	LastModified  string        `xml:"getlastmodified,omitempty"`
	ETag          string        `xml:"getetag,omitempty"`
	ContentType   string        `xml:"getcontenttype,omitempty"`
	SupportedLock supportedLock `xml:"supportedlock"`
}

// supportedLock advertises the handler's lock capabilities. Class 2 support is
// exclusive write locks (RFC 4918 §15.10).
type supportedLock struct {
	LockEntry *lockEntry `xml:"lockentry,omitempty"`
}

type lockEntry struct {
	LockScope lockScope `xml:"lockscope"`
	LockType  lockType  `xml:"locktype"`
}

type resourceType struct {
	Collection *struct{} `xml:"collection,omitempty"`
}

func (h *Handler) propfind(w http.ResponseWriter, r *http.Request, segments []string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPropfindBody+1))
	if err != nil {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	if len(body) > maxPropfindBody {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		var requestBody struct{ XMLName xml.Name }
		if xml.Unmarshal(body, &requestBody) != nil || requestBody.XMLName != (xml.Name{Space: "DAV:", Local: "propfind"}) {
			h.writeError(w, r, fs.ErrInvalid)
			return
		}
	}
	fi, err := h.FileSystem.Stat(r.Context(), fsPath(segments))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	entries := []walkEntry{{fi: fi}}
	switch r.Header.Get("Depth") {
	case "0":
	case "1":
		if fi.IsDir() {
			err = h.walkFS(r, fsPath(segments), nil, false, &entries)
		}
	case "", "infinity":
		if fi.IsDir() {
			err = h.walkFS(r, fsPath(segments), nil, true, &entries)
		}
	default:
		err = fs.ErrInvalid
	}
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	status := multistatus{Responses: make([]propResponse, len(entries))}
	for i, entry := range entries {
		entrySegments := append(append([]string(nil), segments...), entry.segments...)
		status.Responses[i] = h.propertyResponse(entrySegments, entry.fi)
	}
	var output bytes.Buffer
	output.WriteString(xml.Header)
	if err := xml.NewEncoder(&output).Encode(status); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if int64(output.Len()) > h.maxResponseBytes() {
		h.writeError(w, r, errWalkLimit)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = w.Write(output.Bytes())
}

func (h *Handler) propertyResponse(segments []string, fi fs.FileInfo) propResponse {
	displayName := "/"
	if len(segments) > 0 {
		displayName = segments[len(segments)-1]
	}
	properties := properties{
		DisplayName:  displayName,
		LastModified: fi.ModTime().UTC().Format(http.TimeFormat),
		ETag:         entityTag(fi),
	}
	if h.LockSystem != nil {
		properties.SupportedLock.LockEntry = &lockEntry{
			LockScope: lockScope{Exclusive: &struct{}{}},
			LockType:  lockType{Write: &struct{}{}},
		}
	}
	if fi.IsDir() {
		properties.ResourceType.Collection = &struct{}{}
		properties.ContentType = "httpd/unix-directory"
	} else {
		properties.ContentLength = strconv.FormatInt(fi.Size(), 10)
		properties.ContentType = mime.TypeByExtension(path.Ext(displayName))
		if properties.ContentType == "" {
			properties.ContentType = "application/octet-stream"
		}
	}
	return propResponse{
		Href:     h.href(segments, fi.IsDir()),
		Propstat: propstat{Prop: properties, Status: "HTTP/1.1 200 OK"},
	}
}

func (h *Handler) href(segments []string, directory bool) string {
	parts := make([]string, len(segments))
	for i, segment := range segments {
		parts[i] = url.PathEscape(segment)
	}
	href := h.prefixPath()
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
