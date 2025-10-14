#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_ZK_BIN="$SCRIPT_DIR/../zk-code/sig-pop/target/release/examples/run_zk"
PY_DIR="$SCRIPT_DIR/../python-code"

run() {
  echo "> $*"
  "$RUN_ZK_BIN" "$@"
}

CIRCUIT1_DIR="$SCRIPT_DIR/../zk-code/zkp/circuit1"
CIRCUIT2_DIR="$SCRIPT_DIR/../zk-code/zkp/circuit2"
CIRCUIT1_INPUT="$PY_DIR/files/zk/circuit1_inputs.txt"
CIRCUIT2_INPUT="$PY_DIR/files/zk/circuit2_inputs.txt"

if [[ ! -f "$CIRCUIT1_INPUT" || ! -f "$CIRCUIT2_INPUT" ]]; then
  echo "Generate circuit inputs first (e.g., via prepare_inputs_from_public_vector.sh)." >&2
  exit 1
fi

set +e

status=0

prove1_out=$(cd "$CIRCUIT1_DIR" && "$RUN_ZK_BIN" --action prove --compute dot-product-mag --proof-impl mirage --aux-input "$CIRCUIT1_INPUT" 2>&1)
prove1_rc=$?
if [[ $prove1_rc -ne 0 ]]; then
  echo "dot-product-mag prove FAILED"
  echo "$prove1_out"
  status=1
else
  echo "dot-product-mag prove OK"
fi

verify1_out=$(cd "$CIRCUIT1_DIR" && "$RUN_ZK_BIN" --action verify --compute dot-product-mag --proof-impl mirage --aux-input "$CIRCUIT1_INPUT" 2>&1)
verify1_rc=$?
if [[ $verify1_rc -ne 0 ]]; then
  echo "dot-product-mag verify FAILED"
  echo "$verify1_out"
  status=1
else
  echo "dot-product-mag verify OK"
fi

prove2_out=$(cd "$CIRCUIT2_DIR" && "$RUN_ZK_BIN" --action prove --compute combine --proof-impl mirage --aux-input "$CIRCUIT2_INPUT" 2>&1)
prove2_rc=$?
if [[ $prove2_rc -ne 0 ]]; then
  echo "combine prove FAILED"
  echo "$prove2_out"
  status=1
else
  echo "combine prove OK"
fi

verify2_out=$(cd "$CIRCUIT2_DIR" && "$RUN_ZK_BIN" --action verify --compute combine --proof-impl mirage --aux-input "$CIRCUIT2_INPUT" 2>&1)
verify2_rc=$?
if [[ $verify2_rc -ne 0 ]]; then
  echo "combine verify FAILED"
  echo "$verify2_out"
  status=1
else
  echo "combine verify OK"
fi

set -e

if [[ $status -ne 0 ]]; then
  exit $status
fi

echo "Proof generation and verification completed."
