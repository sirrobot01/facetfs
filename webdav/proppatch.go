package webdav

import (
	"bytes"
	"encoding/xml"
	"io"
	"io/fs"
	"net/http"
)

// propertyUpdate is the body of a PROPPATCH request (RFC 4918 §9.2).
type propertyUpdate struct {
	XMLName xml.Name      `xml:"DAV: propertyupdate"`
	Sets    []patchAction `xml:"DAV: set"`
	Removes []patchAction `xml:"DAV: remove"`
}

type patchAction struct {
	Prop namedProps `xml:"DAV: prop"`
}

// namedProps collects the names of the property elements inside a prop
// container without interpreting their values.
type namedProps struct {
	Names []xml.Name
}

func (p *namedProps) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for {
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case xml.StartElement:
			p.Names = append(p.Names, t.Name)
			if err := d.Skip(); err != nil {
				return err
			}
		case xml.EndElement:
			return nil
		}
	}
}

// emptyProp marshals as an empty element carrying its own name and namespace.
type emptyProp struct {
	XMLName xml.Name
}

type patchMultistatus struct {
	XMLName  xml.Name      `xml:"DAV: multistatus"`
	Response patchResponse `xml:"response"`
}

type patchResponse struct {
	Href     string        `xml:"href"`
	Propstat patchPropstat `xml:"propstat"`
}

type patchPropstat struct {
	Prop   patchProp `xml:"prop"`
	Status string    `xml:"status"`
}

type patchProp struct {
	Names []emptyProp
}

// proppatch parses a PROPPATCH request and refuses every property change with
// a 403 propstat: the handler stores no dead properties, and live properties
// are protected. The refusal is atomic, matching RFC 4918 §9.2. Lock and If
// header preconditions are enforced before the refusal, so a locked resource
// answers 423 to a request that carries no token.
func (h *Handler) proppatch(w http.ResponseWriter, r *http.Request, segments []string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPropfindBody+1))
	if err != nil {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	if len(body) > maxPropfindBody {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	p := fsPath(segments)
	fi, err := h.FileSystem.Stat(r.Context(), p)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if !h.checkIf(w, r, segments, entityTag(fi), p) {
		return
	}
	var update propertyUpdate
	if err := xml.Unmarshal(body, &update); err != nil {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	var names []emptyProp
	for _, action := range append(update.Sets, update.Removes...) {
		for _, name := range action.Prop.Names {
			names = append(names, emptyProp{XMLName: name})
		}
	}
	if len(names) == 0 {
		h.writeError(w, r, fs.ErrInvalid)
		return
	}
	status := patchMultistatus{Response: patchResponse{
		Href: h.href(segments, fi.IsDir()),
		Propstat: patchPropstat{
			Prop:   patchProp{Names: names},
			Status: "HTTP/1.1 403 Forbidden",
		},
	}}
	var output bytes.Buffer
	output.WriteString(xml.Header)
	if err := xml.NewEncoder(&output).Encode(status); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = w.Write(output.Bytes())
}
