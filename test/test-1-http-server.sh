#!/usr/bin/env bash

htdocs=htdocs
bind=127.0.0.1

torrent_dir_url="$(grep -m1 torrent_dir_urls test/btcache.config.yaml | cut -d'"' -f2)"

if ! grep -q -E "^http://127\.0\.0\.1[:/]" <<<"$torrent_dir_url"; then
  echo "bad torrent_dir_url: ${torrent_dir_url@Q}"
  exit 1
fi

# torrent_dir_url="http://127.0.0.1:8012/cas/btih/" # test: url with port
# torrent_dir_url="http://127.0.0.1/cas/btih/" # test: url without port

port=$(echo "$torrent_dir_url" | sed -E 's,^http://127\.0\.0\.1(:([0-9]+))?/(.*)$,\2,')
if [ -z "$port" ]; then port=80; fi
echo "port: $port"

path=$(echo "$torrent_dir_url" | sed -E 's,^http://127\.0\.0\.1(:([0-9]+))?/(.*)$,\3,')
echo "path: ${path@Q}"

mkdir -p "$htdocs/$path"

# infohash of test/zero.100mib.bin.torrent
btih=8204399284901c93fc3e024138c7be4288ecb96e

mkdir -p "$htdocs/cas/btih/$btih"

content_file="$htdocs/cas/btih/$btih/zero.100mib.bin"
if ! [ -e "$content_file" ]; then
  ./test/zero.100mib.bin.sh "$content_file"
fi

torrent_file="$htdocs/cas/btih/$btih.torrent"
if ! [ -e "$torrent_file" ]; then
  cp -v test/zero.100mib.bin.torrent "$htdocs/cas/btih/$btih.torrent"
fi

set -x
exec python -m http.server --directory "$htdocs" --bind "$bind" "$port"
