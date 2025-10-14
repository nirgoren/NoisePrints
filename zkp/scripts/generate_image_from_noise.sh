#!/bin/bash
set -euo pipefail


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_DIR="$SCRIPT_DIR/../python-code"

pushd "$PY_DIR" >/dev/null
uv run gen_image_flux.py --noise files/vec_1/vec_1_float.npy --prompt="an image of a dog" --output_prefix "files/output"
echo "Generated image. Latents saved to " 1>&2
popd >/dev/null
