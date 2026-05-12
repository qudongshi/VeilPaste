#!/usr/bin/env sh
set -eu

if ! command -v cargo >/dev/null 2>&1; then
  echo "veilpaste install: cargo is required. Install Rust from https://rustup.rs/" >&2
  exit 1
fi

cargo install --path crates/veilpaste-cli

echo "veilpaste installed. Try: echo 'Authorization: Bearer sk-live-abc1234567890' | veilpaste"
