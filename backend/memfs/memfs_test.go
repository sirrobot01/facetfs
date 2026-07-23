package memfs_test

import (
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/backend/memfs"
	"github.com/sirrobot01/facetfs/backendtest"
)

func TestBackendContract(t *testing.T) {
	backendtest.BackendContract(t, func(*testing.T) facetfs.Backend {
		return memfs.New()
	})
}
