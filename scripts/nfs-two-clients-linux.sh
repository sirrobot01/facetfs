#!/usr/bin/env bash
# Two hosts contend for a byte-range lock, and lease expiry frees the lock of
# a client that died holding it.
#
# Each container is a distinct NFSv4 client with its own clientid. The server
# runs a short lease so the holder's death is observed within the test's
# patience. The holder is killed without unlocking or unmounting: only lease
# expiry can free its lock.
#
# Usage: scripts/nfs-two-clients-linux.sh [port]
set -euo pipefail

port="${1:-20491}"
root="$(mktemp -d)"
holder="nfs-lock-holder-$$"
cleanup() {
	docker rm -f "$holder" >/dev/null 2>&1 || true
	kill "$server" 2>/dev/null || true
	rm -rf "$root"
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
go build -o "$root/nfsd" ./examples/nfs

mkdir -p "$root/export"
: > "$root/export/lockfile"

"$root/nfsd" -addr "0.0.0.0:$port" -root "$root/export" -lease 10s &
server=$!
sleep 1

image=debian:bookworm-slim
prepare='apt-get update -qq && apt-get install -y -qq nfs-common >/dev/null
	mkdir -p /mnt/nfs
	mount -t nfs -o vers=4.0,port=$PORT host.docker.internal:/ /mnt/nfs
'

docker run -d --name "$holder" --cap-add SYS_ADMIN \
	--security-opt apparmor=unconfined \
	--add-host=host.docker.internal:host-gateway \
	-e PORT="$port" "$image" bash -euxc "$prepare"'
	flock -x /mnt/nfs/lockfile -c "touch /mnt/nfs/holder-has-lock && sleep 600"
' >/dev/null

for i in $(seq 1 120); do
	[ -f "$root/export/holder-has-lock" ] && break
	sleep 1
done
test -f "$root/export/holder-has-lock"

docker run --rm --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
	--add-host=host.docker.internal:host-gateway \
	-e PORT="$port" "$image" bash -euxc "$prepare"'
	echo "--- a lock held on another host is refused"
	if flock -n -x /mnt/nfs/lockfile -c true; then
		echo "FAIL: a lock held on another host was granted"
		exit 1
	fi
	touch /mnt/nfs/waiter-was-refused
	echo "--- lease expiry frees a dead holder"
	flock -w 90 -x /mnt/nfs/lockfile -c "echo lock acquired after expiry"
	umount /mnt/nfs
	echo "TWO-CLIENT OK"
' &
waiter=$!

# Once the waiter has observed the refusal, kill the holder abruptly.
for i in $(seq 1 120); do
	[ -f "$root/export/waiter-was-refused" ] && break
	sleep 1
done
test -f "$root/export/waiter-was-refused"
docker kill "$holder" >/dev/null

wait "$waiter"
