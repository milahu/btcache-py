#!/usr/bin/env bash

set -x

of="$1"
if [ -z "$of" ]; then
  of="zero.100mib.bin"
fi

if ! [ -e "$of" ]; then
  # write 100MiB zero bytes to $of
  dd if=/dev/zero count=100 bs=$((1024*1024)) of="$of"
fi
