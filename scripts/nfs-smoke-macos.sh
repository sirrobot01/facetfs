#!/usr/bin/env bash
# Mounts the NFS example from the macOS client and exercises it.
#
# macOS needs root to mount, so this script asks for a password. macOS speaks
# NFSv4.0 only, which is the version this package serves.
#
# Usage: sudo scripts/nfs-smoke-macos.sh [port]
set -euo pipefail

port="${1:-20490}"
mount_point="${TMPDIR:-/tmp}/facetfs-nfs-smoke"
root="$(mktemp -d)"

cleanup() {
	umount "$mount_point" 2>/dev/null || true
	kill "${server:-}" 2>/dev/null || true
	rmdir "$mount_point" 2>/dev/null || true
	rm -rf "$root"
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
go build -o "$root/nfsd" ./examples/nfs

mkdir -p "$root/export/sub"
echo "hello from the server" > "$root/export/greeting.txt"

"$root/nfsd" -addr "127.0.0.1:$port" -root "$root/export" &
server=$!
sleep 1

mkdir -p "$mount_point"
mount -t nfs -o vers=4.0,tcp,port="$port",soft,timeo=50 \
	localhost:/ "$mount_point"

set -x
ls -la "$mount_point"
cat "$mount_point/greeting.txt"

dd if=/dev/urandom of="$root/payload" bs=1m count=8 status=none
cp "$root/payload" "$mount_point/payload"
cmp "$root/payload" "$mount_point/payload"

: > "$mount_point/payload"
test ! -s "$mount_point/payload"

mkdir "$mount_point/newdir"
echo content > "$mount_point/newdir/file"
mv "$mount_point/newdir/file" "$mount_point/newdir/renamed"
test "$(cat "$mount_point/newdir/renamed")" = content
rmdir "$mount_point/sub"
! rmdir "$mount_point/newdir" 2>/dev/null
rm "$mount_point/newdir/renamed" "$mount_point/payload"
rmdir "$mount_point/newdir"

mkdir "$mount_point/many"
for i in $(seq 1 500); do : > "$mount_point/many/f$i"; done
test "$(ls "$mount_point/many" | wc -l | tr -d ' ')" -eq 500
rm -r "$mount_point/many"
set +x

echo "SMOKE OK"
