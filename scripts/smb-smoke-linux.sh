#!/usr/bin/env bash
# Mounts the SMB example from a Linux cifs client and exercises it: criteria
# 3 and 4 of the smb acceptance profile. The server runs on the host with
# signing required, so the mount itself proves the signed session, and every
# transferred byte crosses a connection whose messages the server verifies.
#
# The client runs in a container, because mount.cifs needs a Linux kernel.
# The container needs SYS_ADMIN to mount.
#
# Usage: scripts/smb-smoke-linux.sh [port]
set -euo pipefail

port="${1:-1445}"
if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
	echo "port must be an integer from 1 through 65535" >&2
	exit 2
fi
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

cd "$(dirname "$0")/.."
go build -o "$root/smbd" ./examples/smb

mkdir -p "$root/export/sub"
echo "hello from the host" > "$root/export/greeting.txt"

FACETFS_USER=demo FACETFS_PASSWORD=smoke-test-secret \
	"$root/smbd" -addr "0.0.0.0:$port" -root "$root/export" -require-signing=true &
server=$!
trap 'kill "$server" 2>/dev/null || true; rm -rf "$root"' EXIT
sleep 1
if ! kill -0 "$server" 2>/dev/null; then
	wait "$server"
fi

# mount.cifs re-applies its capability set, so it needs DAC_READ_SEARCH in
# the container on top of the SYS_ADMIN that mounting needs.
docker run --rm --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH \
	--security-opt apparmor=unconfined \
	--add-host=host.docker.internal:host-gateway \
	-e PORT="$port" debian:bookworm-slim bash -euc '
	apt-get update -qq && apt-get install -y -qq cifs-utils >/dev/null
	mkdir -p /mnt/smb
	mount -t cifs -o vers=3.1.1,port=$PORT,username=demo,password=smoke-test-secret,domain=WORKGROUP \
		//host.docker.internal/share /mnt/smb

	echo "--- session state as the client reports it"
	cat /proc/fs/cifs/DebugData || true

	echo "--- listing"
	ls -la /mnt/smb
	echo "--- reading"
	test "$(cat /mnt/smb/greeting.txt)" = "hello from the host"
	echo "--- large copy in both directions"
	dd if=/dev/urandom of=/tmp/payload bs=1M count=8 status=none
	cp /tmp/payload /mnt/smb/payload
	cmp /tmp/payload /mnt/smb/payload
	cp /mnt/smb/payload /tmp/copied-back
	cmp /tmp/payload /tmp/copied-back
	echo "--- renaming"
	mv /mnt/smb/payload /mnt/smb/renamed
	test ! -e /mnt/smb/payload
	cmp /tmp/payload /mnt/smb/renamed
	echo "--- deleting"
	rm /mnt/smb/renamed
	test ! -e /mnt/smb/renamed
	echo "--- directory operations"
	mkdir /mnt/smb/newdir
	echo content > /mnt/smb/newdir/file
	mv /mnt/smb/newdir/file /mnt/smb/newdir/renamed
	test "$(cat /mnt/smb/newdir/renamed)" = content
	rmdir /mnt/smb/sub
	! rmdir /mnt/smb/newdir 2>/dev/null
	rm /mnt/smb/newdir/renamed
	rmdir /mnt/smb/newdir
	echo "--- larger listing"
	mkdir /mnt/smb/many
	for i in $(seq 1 300); do : > /mnt/smb/many/f$i; done
	test "$(ls /mnt/smb/many | wc -l)" -eq 300
	rm -r /mnt/smb/many
	echo "--- remount"
	echo persisted > /mnt/smb/survivor
	umount /mnt/smb
	mount -t cifs -o vers=3.1.1,port=$PORT,username=demo,password=smoke-test-secret,domain=WORKGROUP \
		//host.docker.internal/share /mnt/smb
	test "$(cat /mnt/smb/survivor)" = persisted
	rm /mnt/smb/survivor
	umount /mnt/smb
	echo "SMOKE OK"
'
