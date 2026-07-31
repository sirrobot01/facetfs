#!/usr/bin/env bash
# Measures what a read delegation saves a Linux client.
#
# Server and client run in the same container, so the client's callback
# listener is reachable and the server grants delegations. The measurement:
# once the client holds a read delegation, re-reading the file must reach the
# server with (almost) no requests, where an undelegated re-read pays OPEN,
# GETATTR, and CLOSE every time.
#
# Usage: scripts/nfs-deleg-linux.sh
set -euo pipefail

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

cd "$(dirname "$0")/.."
arch="$(docker version --format '{{.Server.Arch}}')"
GOOS=linux GOARCH="$arch" go build -o "$root/nfsd" ./examples/nfs

mkdir -p "$root/export"
head -c 65536 /dev/urandom > "$root/export/data.bin"

docker run --rm --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
	-v "$root:/work" debian:bookworm-slim bash -euxc '
	apt-get update -qq && apt-get install -y -qq nfs-common >/dev/null

	/work/nfsd -addr 127.0.0.1:2049 -root /work/export -delegations &
	sleep 1
	mkdir -p /mnt/nfs
	mount -t nfs -o vers=4.0,port=2049,soft,timeo=50 127.0.0.1:/ /mnt/nfs

	# Total NFS client RPC calls so far, from /proc/net/rpc/nfs.
	calls() { awk "/^rpc/ {print \$2}" /proc/net/rpc/nfs; }

	# The first read confirms the open-owner; the second is granted the
	# delegation. Only then is the re-read measured.
	cat /mnt/nfs/data.bin > /dev/null
	cat /mnt/nfs/data.bin > /dev/null
	before=$(calls)
	cat /mnt/nfs/data.bin > /dev/null
	after=$(calls)
	spent=$((after - before))
	echo "RPCs for the delegated re-read: $spent"

	umount /mnt/nfs
	if [ "$spent" -gt 1 ]; then
		echo "DELEG FAIL: the re-read still reached the server $spent times"
		exit 1
	fi
	echo "DELEG OK"
'
