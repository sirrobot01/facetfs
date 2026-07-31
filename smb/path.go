package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"path"
	"strings"
	"unicode/utf16"

	"github.com/sirrobot01/facetfs/internal/names"
)

var errSMBName = errors.New("smb: invalid path name")

func decodeUTF16(b []byte) (string, bool) {
	if len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
		if 0xd800 <= u[i] && u[i] <= 0xdbff {
			if i+1 >= len(u) {
				return "", false
			}
			n := binary.LittleEndian.Uint16(b[(i+1)*2:])
			if n < 0xdc00 || n > 0xdfff {
				return "", false
			}
		} else if 0xdc00 <= u[i] && u[i] <= 0xdfff && (i == 0 || u[i-1] < 0xd800 || u[i-1] > 0xdbff) {
			return "", false
		}
	}
	return string(utf16.Decode(u)), true
}

var dosNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func smbPath(wire []byte) (string, error) {
	if len(wire) > maxPathBytes {
		return "", errSMBName
	}
	s, ok := decodeUTF16(wire)
	if !ok || strings.HasPrefix(s, "\\") || strings.ContainsRune(s, 0) {
		return "", errSMBName
	}
	if s == "" {
		return "/", nil
	}
	parts := strings.Split(s, "\\")
	for _, part := range parts {
		base := part
		if dot := strings.IndexByte(base, '.'); dot >= 0 {
			base = base[:dot]
		}
		if err := names.Validate(part); err != nil || dosNames[strings.ToUpper(strings.TrimRight(base, " ."))] {
			return "", errSMBName
		}
	}
	p := "/" + strings.Join(parts, "/")
	if path.Clean(p) != p {
		return "", errSMBName
	}
	return p, nil
}

func pathStatus(err error) uint32 {
	if err == nil {
		return statusSuccess
	}
	if errors.Is(err, errSMBName) {
		return statusObjectNameInvalid
	}
	return fsStatus(err)
}

func fsStatus(err error) uint32 {
	if err == nil {
		return statusSuccess
	}
	if st, ok := errnoStatus(err); ok {
		return st
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return statusObjectNameNotFound
	case errors.Is(err, fs.ErrExist):
		return statusObjectNameCollision
	case errors.Is(err, fs.ErrPermission):
		return statusAccessDenied
	case errors.Is(err, fs.ErrInvalid):
		return statusInvalidParameter
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return statusCancelled
	default:
		return statusUnsuccessful
	}
}
