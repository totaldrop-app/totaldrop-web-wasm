#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated WASM Target Build Unit: wasm32-unknown-unknown (baseline)
#
# Compiles `totaldrop-wasm` without `simd128` instructions as a portable
# fallback for restricted WebViews or legacy engines where `supportsWasmSimd128()`
# returns false, and emits a SHA-384 Subresource Integrity (`sha384-...`)
# manifest for `web-ui/receiver.js`.

set -euo pipefail

UNIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$UNIT_DIR/.." && pwd)"
DIST_DIR="$UNIT_DIR/dist"
TARGET_TRIPLE="wasm32-unknown-unknown"
WASM_RUSTFLAGS='-D warnings -C target-feature=-simd128'

if [[ -z "${RUSTUP_TOOLCHAIN:-}" ]] && ! rustup show active-toolchain >/dev/null 2>&1; then
  export RUSTUP_TOOLCHAIN="stable"
fi

generate_sri() {
  local file_path="$1"
  python3 - "$file_path" <<'PY'
import base64, hashlib, sys
with open(sys.argv[1], "rb") as f:
    digest = hashlib.sha384(f.read()).digest()
print("sha384-" + base64.b64encode(digest).decode("ascii"))
PY
}

if [[ "${1:-}" == "--sri-file" ]]; then
  generate_sri "${2:?missing file path for --sri-file}"
  exit 0
fi

if [[ "${1:-}" == "--dry-run" ]]; then
  echo "Variant:       wasm32-baseline"
  echo "Toolchain:     ${RUSTUP_TOOLCHAIN:-$(rustup show active-toolchain | awk '{print $1}')}"
  echo "RUSTFLAGS:     $WASM_RUSTFLAGS"
  echo "Build command: cargo build --target $TARGET_TRIPLE --release -p totaldrop-wasm"
  exit 0
fi

INSTALLED_TARGETS="$(rustup target list --installed 2>/dev/null || true)"
if ! grep -qx "$TARGET_TRIPLE" <<<"$INSTALLED_TARGETS"; then
  echo "error: target '$TARGET_TRIPLE' is not installed in toolchain '${RUSTUP_TOOLCHAIN:-active}'." >&2
  echo "Install it first: rustup target add $TARGET_TRIPLE" >&2
  exit 1
fi

mkdir -p "$DIST_DIR"
cd "$ROOT_DIR"

RUSTFLAGS="$WASM_RUSTFLAGS" cargo build \
  --target "$TARGET_TRIPLE" \
  --target-dir "$UNIT_DIR/target" \
  --release \
  -p totaldrop-wasm \
  "$@"

WASM_OUT="$UNIT_DIR/target/$TARGET_TRIPLE/release/totaldrop_wasm.wasm"
cp "$WASM_OUT" "$DIST_DIR/totaldrop_wasm.baseline.wasm"

SRI="$(generate_sri "$DIST_DIR/totaldrop_wasm.baseline.wasm")"
SIZE_BYTES="$(wc -c <"$DIST_DIR/totaldrop_wasm.baseline.wasm" | tr -d ' ')"

printf '%s\n' "$SRI" >"$DIST_DIR/totaldrop_wasm.baseline.wasm.sri"
cat >"$DIST_DIR/manifest.json" <<EOF
{
  "variant": "baseline",
  "target": "$TARGET_TRIPLE",
  "rustflags": "-D warnings -C target-feature=-simd128",
  "artifact": "totaldrop_wasm.baseline.wasm",
  "bytes": $SIZE_BYTES,
  "integrity": "$SRI"
}
EOF

echo "Built $DIST_DIR/totaldrop_wasm.baseline.wasm ($SIZE_BYTES bytes)"
echo "Integrity: $SRI"
