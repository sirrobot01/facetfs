//go:build !linux

package facetcache

import "os"

// punchSupported gates the janitor's punch-behind phase. Without hole
// punching the disk budget stays soft against open files; Stats reports the
// overshoot.
const punchSupported = false

func punchHole(f *os.File, off, size int64) error { return nil }
