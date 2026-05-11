#!/bin/sh

set -x

rm -rf test-leecher-downloads/ btcache-test-leecher-downloads/

exec ./src/btcache/btcache_test_leecher.py --peer 127.0.0.1:6880 --listen 127.0.0.1:6882 --btih 5ede438324226f349943aad4ca7d23dc9c08feb3
