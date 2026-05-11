#!/bin/sh

set -x

rm -rf test-leecher-downloads/ btcache-test-leecher-downloads/

btih=$(
  ls htdocs/cas/btih/*.torrent |
  head -n1 |
  xargs basename --suffix=.torrent
)
if [ -z "$btih" ]; then
  echo "error: no .torrent files in htdocs/cas/btih/"
  exit 1
fi
echo "btih: ${btih@Q}"

exec ./src/btcache/btcache_test_leecher.py --peer 127.0.0.1:6881 --listen 127.0.0.1:6882 --btih "$btih" --enable-seeding
