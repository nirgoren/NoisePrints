#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: prepare_inputs_from_public_vector.sh --public-vector <path.npy> [--threshold <float>] [--threshold-fixed <int>]

Options:
  -p, --public-vector    Path to the .npy file with the public vector (float tensor).
  -t, --threshold        Cosine similarity threshold as a float (converted to Q32.32).
      --threshold-fixed  Threshold already expressed as a Q32.32 integer.
  -h, --help             Show this message.
EOF
  exit 1
}

PUBLIC_VECTOR=""
THRESHOLD=""
THRESHOLD_FIXED=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--public-vector)
      PUBLIC_VECTOR="$2"
      shift 2
      ;;
    -t|--threshold)
      THRESHOLD="$2"
      shift 2
      ;;
    --threshold-fixed)
      THRESHOLD_FIXED="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
done

if [[ -z "$PUBLIC_VECTOR" ]]; then
  echo "Error: --public-vector is required." >&2
  usage
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_DIR="$SCRIPT_DIR/../python-code"

pushd "$PY_DIR" >/dev/null
CMD=(python3 gen_zk_inputs.py --public-vector "$PUBLIC_VECTOR")

if [[ -n "$THRESHOLD" ]]; then
  CMD+=(--threshold "$THRESHOLD")
fi

if [[ -n "$THRESHOLD_FIXED" ]]; then
  CMD+=(--threshold-fixed "$THRESHOLD_FIXED")
fi

"${CMD[@]}"
popd >/dev/null
