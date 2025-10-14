#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 <seed1>"
  exit 1
}

if [[ $# -ne 1 ]]; then
  usage
fi

SEED="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_DIR="$SCRIPT_DIR/../python-code"

pushd "$PY_DIR" >/dev/null
python3 gen_vec_1.py "$SEED"
echo "Generated seed $SEED. Outputs written to files/vec_1/ (including vec_1_float.npy)." 1>&2
popd >/dev/null
