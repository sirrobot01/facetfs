#!/usr/bin/env bash
# Mounts the NFS example from a Linux client and exercises it.
#
# The server runs on the host and the client runs in a container, because a
# Linux NFS client needs a Linux kernel. The container needs SYS_ADMIN to
# mount.
#
# Usage: scripts/nfs-smoke-linux.sh [port]
set -euo pipefail

port="${1:-20490}"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

cd "$(dirname "$0")/.."
go build -o "$root/nfsd" ./examples/nfs

mkdir -p "$root/export"
echo "hello from the host" > "$root/export/greeting.txt"
mkdir -p "$root/export/sub"

# Delegations stay enabled: the container's callback listener is not
# reachable from the host, which is exactly the unreachable-callback case the
# server must serve without granting or slowing anything.
"$root/nfsd" -addr "0.0.0.0:$port" -root "$root/export" -delegations &
server=$!
trap 'kill $server 2>/dev/null || true; rm -rf "$root"' EXIT
sleep 1

docker run --rm --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
	--add-host=host.docker.internal:host-gateway \
	-e PORT="$port" debian:bookworm-slim bash -euxc '
	apt-get update -qq && apt-get install -y -qq nfs-common socat procps >/dev/null
	mkdir -p /mnt/nfs
	# Locking is left on so the server-side LOCK operations are exercised.
	mount -t nfs -o vers=4.0,port=$PORT,soft,timeo=50 \
		host.docker.internal:/ /mnt/nfs

	echo "--- listing"
	ls -la /mnt/nfs
	echo "--- reading"
	cat /mnt/nfs/greeting.txt
	echo "--- writing"
	dd if=/dev/urandom of=/tmp/payload bs=1M count=8 status=none
	cp /tmp/payload /mnt/nfs/payload
	cmp /tmp/payload /mnt/nfs/payload
	echo "--- truncating open"
	: > /mnt/nfs/payload
	test ! -s /mnt/nfs/payload
	echo "--- directory operations"
	mkdir /mnt/nfs/newdir
	echo content > /mnt/nfs/newdir/file
	mv /mnt/nfs/newdir/file /mnt/nfs/newdir/renamed
	test "$(cat /mnt/nfs/newdir/renamed)" = content
	rmdir /mnt/nfs/sub
	! rmdir /mnt/nfs/newdir 2>/dev/null
	rm /mnt/nfs/newdir/renamed /mnt/nfs/payload
	rmdir /mnt/nfs/newdir
	echo "--- large listing"
	mkdir /mnt/nfs/many
	for i in $(seq 1 500); do : > /mnt/nfs/many/f$i; done
	test "$(ls /mnt/nfs/many | wc -l)" -eq 500
	rm -r /mnt/nfs/many

	echo "--- byte-range locks between two processes"
	: > /mnt/nfs/lockfile
	flock -x /mnt/nfs/lockfile -c "sleep 3" &
	holder=$!
	sleep 1
	# The lock is held, so a second taker must not get it.
	if flock -w 1 -x /mnt/nfs/lockfile -c true; then
		echo "FAIL: a held lock was granted to a second process"
		exit 1
	fi
	wait $holder
	# Once released it is available again.
	flock -w 5 -x /mnt/nfs/lockfile -c true
	rm /mnt/nfs/lockfile

	echo "--- disconnect with work in flight"
	# The mount goes through a local proxy so the connection can be cut while
	# operations are running. The mount is hard: the client must retry and
	# reconnect, and every operation must land exactly once.
	socat TCP-LISTEN:2050,fork,reuseaddr TCP:host.docker.internal:$PORT &
	mkdir -p /mnt/nfs2
	mount -t nfs -o vers=4.0,port=2050 127.0.0.1:/ /mnt/nfs2
	mkdir /mnt/nfs2/burst
	(
		for i in $(seq 1 300); do
			echo "payload $i" > /mnt/nfs2/burst/f$i
			flock -x /mnt/nfs2/burst/f$i -c true
		done
		touch /tmp/burst-done
	) &
	# Cut every connection part way through, then bring the path back.
	while [ ! -e /mnt/nfs2/burst/f100 ]; do sleep 0.1; done
	pkill -x socat
	test ! -f /tmp/burst-done # the cut must land while work is in flight
	sleep 2
	socat TCP-LISTEN:2050,fork,reuseaddr TCP:host.docker.internal:$PORT &
	for i in $(seq 1 120); do
		[ -f /tmp/burst-done ] && break
		sleep 1
	done
	test -f /tmp/burst-done
	test "$(ls /mnt/nfs2/burst | wc -l)" -eq 300
	for i in $(seq 1 300); do
		test "$(cat /mnt/nfs2/burst/f$i)" = "payload $i"
	done
	rm -r /mnt/nfs2/burst
	umount /mnt/nfs2

	echo "--- remount"
	echo persisted > /mnt/nfs/survivor
	umount /mnt/nfs
	mount -t nfs -o vers=4.0,port=$PORT,soft,timeo=50 \
		host.docker.internal:/ /mnt/nfs
	test "$(cat /mnt/nfs/survivor)" = persisted
	rm /mnt/nfs/survivor

	umount /mnt/nfs
	echo "SMOKE OK"
'
