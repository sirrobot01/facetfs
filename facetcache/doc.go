// Package facetcache wraps a slow facetfs.FileSystem and serves reads from
// local disk. The application composes it between a remote backend and a
// protocol server; every protocol package benefits without change.
//
// The package keeps two caches. An attribute cache answers Stat and Lstat
// from memory with a short TTL. A content cache stores file bytes in one
// sparse file per object, tracks exactly which byte ranges are present,
// fills missing ranges from the backend with read-ahead, and deduplicates
// concurrent fetches of the same region. Cached content persists across
// restarts and is validated against the backend by a size+mtime fingerprint.
//
// Writes go through: the backend must acknowledge a write before the cache
// stores it, so the cache never holds bytes the backend does not.
//
// The cache is coherent only while this process is the sole writer to the
// backend. A write that arrives outside it — through another process or from
// the application itself against the backend directly — invalidates nothing,
// so clients would keep reading stale attributes until the TTL expires and
// stale content until the fingerprint changes on a cold open. Do not wrap a
// backend that is mutated behind the cache's back.
package facetcache
