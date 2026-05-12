#!/usr/bin/env bash

cache_path="btcache-downloads/"

last_size=

while true; do

  size_actual=$(du -s -BMiB "$cache_path" | cut -d$'\t' -f1)
  size_apparent=$(du -s -BMiB -A "$cache_path" | cut -d$'\t' -f1)
  size="$size_actual / $size_apparent"
  if [[ "$size" != "$last_size" ]]; then
    echo "$(date -Is) $size"
    last_size="$size"
  fi
  sleep 1

done
