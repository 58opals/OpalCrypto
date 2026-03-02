#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: Tools/public-api/validate-public-surface.sh [--update-baseline]
USAGE
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

update_baseline=false
if [[ "${1:-}" == "--update-baseline" ]]; then
  update_baseline=true
  shift
fi

if [[ "$#" -ne 0 ]]; then
  usage
  exit 2
fi

echo "[INFO] Validating OpalCrypto public surface"

violations="$(rg -n '\b(public|open)\b' Sources/OpalCrypto --glob '!Sources/OpalCrypto/PublicAPI/**' || true)"
if [[ -n "$violations" ]]; then
  echo "[FAIL] Found public/open declarations outside Sources/OpalCrypto/PublicAPI"
  echo "$violations"
  exit 1
fi

echo "[PASS] Rule 1: no public/open declarations outside PublicAPI"

swift package dump-symbol-graph --minimum-access-level public >/dev/null

symbol_graph_file="$(find .build -type f -path '*/symbolgraph/OpalCrypto.symbols.json' | head -n 1)"
if [[ -z "$symbol_graph_file" ]]; then
  echo "[FAIL] Unable to locate OpalCrypto symbol graph output in .build"
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/opalcrypto-public-api.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

snapshot_file="$tmp_dir/opalcrypto-public-api.txt"
baseline_file="Tools/public-api/baseline/opalcrypto-public-api.txt"

jq -r '
  .symbols
  | to_entries[]
  | .value
  | [
      .identifier.precise,
      ((.pathComponents // []) | join(".")),
      ((.declarationFragments // []) | map(.spelling) | join(""))
    ]
  | @tsv
' "$symbol_graph_file" | LC_ALL=C sort > "$snapshot_file"

denylist=(
  EllipticCurveDigitalSignatureAlgorithmModel
  SchnorrSignatureModel
  StandardsForEfficientCryptography256k1CurveModel
  NonceGenerationPolicy
  Unsigned256BitIntegerModel
  Unsigned512BitIntegerModel
  LargeUnsignedIntegerArithmeticModel
)

for denied in "${denylist[@]}"; do
  if grep -Fq "$denied" "$snapshot_file"; then
    echo "[FAIL] Rule 3 violated: internal type leaked into public API snapshot: $denied"
    grep -Fn "$denied" "$snapshot_file"
    exit 1
  fi
done

echo "[PASS] Rule 3: no known internal type leaks"

if [[ "$update_baseline" == true ]]; then
  mkdir -p "$(dirname "$baseline_file")"
  cp "$snapshot_file" "$baseline_file"
  echo "[PASS] Baseline updated: $baseline_file"
  exit 0
fi

if [[ ! -f "$baseline_file" ]]; then
  echo "[FAIL] Baseline missing: $baseline_file"
  echo "[INFO] Run with --update-baseline after intentional API changes"
  exit 1
fi

if ! diff -u "$baseline_file" "$snapshot_file"; then
  echo "[FAIL] Rule 2 violated: public API baseline drift detected"
  echo "[INFO] If intentional, regenerate with --update-baseline"
  exit 1
fi

echo "[PASS] Rule 2: public API baseline matches"
