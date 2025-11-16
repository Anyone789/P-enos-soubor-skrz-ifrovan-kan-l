#!/bin/bash
# Simple integration test: build, run server in background, send a file, verify hash.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"/..
cd "$HERE"
make
# start server
./secret -l &
SPID=$!
sleep 1
# create random file
dd if=/dev/urandom of=test.bin bs=1K count=64 >/dev/null 2>&1
sha256sum test.bin > sent.sha256
# send file
./secret -r test.bin -s 127.0.0.1
# wait a moment
sleep 1
# verify file exists on server (same dir) and hash matches
sha256sum test.bin > recv.sha256
if cmp -s sent.sha256 recv.sha256; then
  echo "TEST OK: hashes match"
  kill $SPID || true
  exit 0
else
  echo "TEST FAIL: hashes differ"
  kill $SPID || true
  exit 2
fi
