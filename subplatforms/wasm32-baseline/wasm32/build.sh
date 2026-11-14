#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated sub-platform build entry point for `web-wasm32-baseline-wasm32` (ADR 0020).

set -eu

UNIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$UNIT_DIR/../../.." && pwd)
RECIPE="$UNIT_DIR/RECIPE.toml"
DELEGATE="$REPO_ROOT/target-wasm32-baseline/build.sh"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1760000000}"

if [ "${1:-}" = "--check-recipe" ]; then
  [ -f "$RECIPE" ] || { echo "missing $RECIPE" >&2; exit 1; }
  [ -e "$DELEGATE" ] || { echo "missing upstream delegate $DELEGATE" >&2; exit 1; }
  grep -q 'unit_id = "web-wasm32-baseline-wasm32"' "$RECIPE"
  grep -q 'artifact_name = "totaldrop-web-wasm-0.3.0-beta.6-baseline.tar.gz"' "$RECIPE"
  echo "recipe check ok: web-wasm32-baseline-wasm32 -> totaldrop-web-wasm-0.3.0-beta.6-baseline.tar.gz"
  exit 0
fi

if [ "${1:-}" = "--package-staged" ]; then
  STAGE_IN="${2:?missing staging input directory}"
  OUT_DIR="${3:?missing output directory}"
  stage_root=$(mktemp -d)
  trap 'rm -rf "$stage_root"' EXIT
  pkg_root="$stage_root/totaldrop-web-wasm-0.3.0-beta.6-wasm32-baseline"
  mkdir -p "$pkg_root/wasm" "$pkg_root/web-ui" "$pkg_root/LICENSES"
  for wasm_f in "$STAGE_IN"/*.wasm "$STAGE_IN"/*.sri; do
    [ -f "$wasm_f" ] && cp "$wasm_f" "$pkg_root/wasm/"
  done
  cp -R "$REPO_ROOT/web-ui/index.html" "$REPO_ROOT/web-ui/styles.css" "$REPO_ROOT/web-ui/receiver.js" "$REPO_ROOT/web-ui/transport.js" "$REPO_ROOT/web-ui/fs-writer.js" "$REPO_ROOT/web-ui/i18n" "$pkg_root/web-ui/"
  cp "$REPO_ROOT/LICENSES/"*.txt "$pkg_root/LICENSES/"
  mkdir -p "$OUT_DIR"
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-1760000000}" --owner=0 --group=0 --numeric-owner -cf - -C "$stage_root" "totaldrop-web-wasm-0.3.0-beta.6-wasm32-baseline" | gzip -n >"$OUT_DIR/totaldrop-web-wasm-0.3.0-beta.6-baseline.tar.gz"
  (cd "$OUT_DIR" && sha256sum "totaldrop-web-wasm-0.3.0-beta.6-baseline.tar.gz" >SHA256SUMS)
  echo "packaged web-wasm32-baseline-wasm32 -> $OUT_DIR/totaldrop-web-wasm-0.3.0-beta.6-baseline.tar.gz"
  exit 0
fi

OUT_DIR="${1:-$REPO_ROOT/dist/wasm32-baseline/wasm32}"
mkdir -p "$OUT_DIR"

case "$DELEGATE" in
  *.sh)
    sh "$DELEGATE"
    ;;
  *.ps1)
    pwsh -NoProfile -File "$DELEGATE"
    ;;
  *)
    echo "Verified delegate configuration: $DELEGATE (Rust target: wasm32-unknown-unknown)"
    ;;
esac
