#!/bin/sh

set -x

rm -rf btcache-downloads/ btcache-torrents/

exec ./src/btcache/btcache.py --config test/btcache.config.yaml
