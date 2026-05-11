#!/bin/sh

set -x

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

torrent="htdocs/cas/btih/$btih.torrent"
save="htdocs/cas/btih/$btih"

exec ./src/btcache/btcache_seeder.py --torrent "$torrent" --save "$save" --allowed-peers 127.0.0.1 --listen 127.0.0.1:6880
