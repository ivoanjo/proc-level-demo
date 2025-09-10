#!/usr/bin/env bash
set -euo pipefail

# Unless explicitly stated otherwise all files in this repository are licensed under the Apache License (Version 2.0).
# This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog, Inc.

# otel_process_ctx_dump.sh
# Usage: ./otel_process_ctx_dump.sh <pid>
#
# Reads the OTEL process context mapping for a given PID, parses the struct,
# and dumps the payload as well.

check_otel_signature() {
  # Check that the first 8 bytes are "OTEL_CTX"
  [ "$(printf '%s' "$1" | base64 -d | dd bs=1 count=8 status=none)" = "OTEL_CTX" ]
}

if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: this script only supports Linux." >&2
  exit 1
fi

pid="${1:-}"
if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <pid>" >&2
  exit 1
fi

# Can we use the name of the mapping to find the context? This works on modern (5.17+) Linux versions
kernel_version=$(uname -r | cut -d. -f1,2)
major_version=$(echo "$kernel_version" | cut -d. -f1)
minor_version=$(echo "$kernel_version" | cut -d. -f2)

if [ "$major_version" -ge 5 ] && { [ "$major_version" -gt 5 ] || [ "$minor_version" -ge 17 ]; }; then
  line="$(grep -F '[anon:OTEL_CTX]' "/proc/$pid/maps" | head -n 1)"
  if [ -z "$line" ]; then
    echo "No [anon:OTEL_CTX] mapping found for PID $pid." >&2
    exit 1
  fi

  start_addr="${line%%-*}"
else
  # Legacy kernel - scan for anonymous mappings that could be OTEL_CTX
  while IFS= read -r line; do
    # Parse start-end addresses and check if line contains required characteristics
    if [[ "$line" =~ "00:00 0" ]] && \
       [[ "$line" =~ r--p ]] && \
       [[ "$line" =~ ^([0-9a-f]+)-([0-9a-f]+) ]]; then

      start_addr_hex="${BASH_REMATCH[1]}"
      end_addr_hex="${BASH_REMATCH[2]}"
      size=$((16#$end_addr_hex - 16#$start_addr_hex))

      # Check if size is 8192 bytes and verify signature
      if [ "$size" -eq 8192 ]; then
        candidate_data_b64="$(dd if="/proc/$pid/mem" bs=1 count=8 skip=$((16#$start_addr_hex)) status=none 2>/dev/null | base64 -w0)"
        if check_otel_signature "$candidate_data_b64"; then
          start_addr="$start_addr_hex"
          break
        fi
      fi
    fi
  done < "/proc/$pid/maps"

  if [ -z "${start_addr:-}" ]; then
    echo "No OTEL_CTX context found on legacy kernel." >&2
    exit 1
  fi
fi

echo "Found OTEL context for PID $pid"
echo "Start address: $start_addr"

# Read struct otel_process_ctx_mapping, encode as base64 so we can safely store it in a shell variable.
# (Bash variables cannot hold NUL bytes, so raw binary causes issues)
data_b64="$(dd if="/proc/$pid/mem" bs=1 count=24 skip=$((16#$start_addr)) status=none | base64 -w0)"

# Pretty-print otel_process_ctx_mapping
printf '%s' "$data_b64" | base64 -d | hexdump -C

# Check that the first 8 bytes are "OTEL_CTX"
check_otel_signature "$data_b64"

# Extract fields from otel_process_ctx_mapping
signature="$(
  printf '%s' "$data_b64" | base64 -d | dd bs=1 count=8 status=none
)"
version="$(
  printf '%s' "$data_b64" | base64 -d | dd bs=1 skip=8 count=4 status=none | od -An -t u4 | tr -d ' '
)"
payload_size="$(
  printf '%s' "$data_b64" | base64 -d | dd bs=1 skip=12 count=4 status=none | od -An -t u4 | tr -d ' '
)"
payload_ptr_hex="$(
  printf '%s' "$data_b64" | base64 -d | dd bs=1 skip=16 count=8 status=none | od -An -t x8 | tr -d ' '
)"

echo "Parsed struct:"
echo "  otel_process_ctx_signature : \"$signature\""
echo "  otel_process_ctx_version   : $version"
echo "  otel_process_payload_size  : $payload_size"
echo "  otel_process_payload       : 0x$payload_ptr_hex"

# Dump payload if size > 0
if [ "$payload_size" -gt 0 ]; then
  echo
  echo "Payload dump ($payload_size bytes):"
  dd if="/proc/$pid/mem" bs=1 count="$payload_size" skip=$((16#$payload_ptr_hex)) status=none | hexdump -C
else
  echo
  echo "Payload is empty."
fi
