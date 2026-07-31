package nfs4

import (
	"crypto/hmac"
	"crypto/sha256"
	"sync"
)

// Filehandles are HMAC-sealed cleaned paths, advertised as volatile
// (FH4_VOLATILE_ANY): clients see NFS4ERR_FHEXPIRED or NFS4ERR_STALE when one
// stops resolving. Rename always invalidates a handle. Restart invalidates
// handles only under a per-Server random key; a fixed Server.HandleKey keeps
// short handles valid. Long handles also depend on the sha→path table below,
// so eviction and restart expire them unless a resolver re-derives the path.
//
// Short form, paths up to shortPathMax bytes: 0x01 ‖ mac[16] ‖ path.
// Long form: 0x02 ‖ mac[16] ‖ sha256(path); the sha→path mapping is kept in a
// bounded table populated when the handle is issued. Truncated-MAC forgery
// and SHA-256 collisions are outside the threat model.
const (
	fhShort = 0x01
	fhLong  = 0x02

	fhMacLen     = 16
	shortPathMax = maxFHBytes - fhMacLen - 1
	longTableMax = 4096
)

type fhCodec struct {
	key     []byte
	resolve func(sum [32]byte) (string, bool)

	mu    sync.Mutex
	long  map[[32]byte]string
	order [][32]byte // FIFO eviction; oldest first
}

func newFHCodec(key []byte, resolve func(sum [32]byte) (string, bool)) *fhCodec {
	return &fhCodec{key: key, resolve: resolve, long: map[[32]byte]string{}}
}

func (c *fhCodec) remember(sum [32]byte, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.long[sum]; ok {
		return
	}
	if len(c.order) >= longTableMax {
		delete(c.long, c.order[0])
		c.order = c.order[1:]
	}
	c.long[sum] = path
	c.order = append(c.order, sum)
}

func (c *fhCodec) mac(form byte, payload []byte) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte{form})
	m.Write(payload)
	return m.Sum(nil)[:fhMacLen]
}

func (c *fhCodec) seal(path string) []byte {
	if len(path) <= shortPathMax {
		fh := make([]byte, 0, 1+fhMacLen+len(path))
		fh = append(fh, fhShort)
		fh = append(fh, c.mac(fhShort, []byte(path))...)
		return append(fh, path...)
	}
	sum := sha256.Sum256([]byte(path))
	c.remember(sum, path)
	fh := make([]byte, 0, 1+fhMacLen+len(sum))
	fh = append(fh, fhLong)
	fh = append(fh, c.mac(fhLong, sum[:])...)
	return append(fh, sum[:]...)
}

func (c *fhCodec) unseal(fh []byte) (string, nfsStat) {
	if len(fh) < 1+fhMacLen || len(fh) > maxFHBytes {
		return "", nfs4ErrBadHandle
	}
	form, mac, payload := fh[0], fh[1:1+fhMacLen], fh[1+fhMacLen:]
	switch form {
	case fhShort:
		if !hmac.Equal(mac, c.mac(fhShort, payload)) {
			return "", nfs4ErrFHExpired
		}
		return string(payload), nfs4OK
	case fhLong:
		if len(payload) != sha256.Size || !hmac.Equal(mac, c.mac(fhLong, payload)) {
			return "", nfs4ErrFHExpired
		}
		sum := [32]byte(payload)
		c.mu.Lock()
		path, ok := c.long[sum]
		c.mu.Unlock()
		if !ok && c.resolve != nil {
			if p, found := c.resolve(sum); found && sha256.Sum256([]byte(p)) == sum {
				c.remember(sum, p)
				path, ok = p, true
			}
		}
		if !ok {
			return "", nfs4ErrFHExpired
		}
		return path, nfs4OK
	default:
		return "", nfs4ErrBadHandle
	}
}
