//go:build !linux && !darwin && !windows

package facetcache

import "os"

// punchSupported gates the janitor's punch-behind phase. Without hole
// punching the disk budget stays soft against open files; Stats reports the
// overshoot.
const punchSupported = false

const punchAlign = 1

func punchHole(f *os.File, off, size int64) error { return nil }

func markSparse(f *os.File) error { return nil }
