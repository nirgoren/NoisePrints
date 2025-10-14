#!/bin/bash

CIRC_PATH="./../../sig-pop/target/release/examples/circ"
RUN_ZK_PATH="./../../sig-pop/target/release/examples/run_zk"

# CIRCUIT_1_INPUT="../../../python-code/inputs/circuit1_inputs.txt"
# CIRCUIT_2_INPUT="../../../python-code/inputs/circuit2_inputs.txt"

CIRCUIT_1_INPUT="../../../python-code/files/zk/circuit1_inputs.txt"
CIRCUIT_2_INPUT="../../../python-code/files/zk/circuit2_inputs.txt"


cd ../zk-code/zkp/circuit1

results=()
for i in $(seq 1 5); do
   output=$($RUN_ZK_PATH --action prove --compute dot-product-mag --proof-impl mirage --aux-input $CIRCUIT_1_INPUT)
   time_line=$(echo "$output" | awk 'NR==2')
   exact_time_w_unit=$(echo "$time_line" | awk '{print $5}')
   results+=("$exact_time_w_unit")
done

sorted=($(printf "%s\n" "${results[@]}" | sort -g))
# echo "${sorted[@]}"
median=${sorted[2]}
# echo "(Offline) prover time to blind (median over 5 iterations): $median"
echo "Time to gen proof for dot product and magnitude square: $median"

results=()
for i in $(seq 1 5); do
   output=$($RUN_ZK_PATH --action verify --compute dot-product-mag --proof-impl mirage --aux-input $CIRCUIT_1_INPUT)
   time_line=$(echo "$output" | awk 'NR==2')
   exact_time_w_unit=$(echo "$time_line" | awk '{print $5}')
   results+=("$exact_time_w_unit")
done

sorted=($(printf "%s\n" "${results[@]}" | sort -g))
median_veri1=${sorted[2]}
echo "Time to verify proof for dot product and magnitude square: $median_veri1"


cd ../circuit2
results=()
for i in $(seq 1 5); do
   output=$($RUN_ZK_PATH --action prove --compute combine --proof-impl mirage --aux-input $CIRCUIT_2_INPUT)
   time_line=$(echo "$output" | awk 'NR==2')
   exact_time_w_unit=$(echo "$time_line" | awk '{print $5}')
   results+=("$exact_time_w_unit")
done

sorted=($(printf "%s\n" "${results[@]}" | sort -g))
# echo "${sorted[@]}"
median=${sorted[2]}
# echo "(Offline) prover time to revoke (median over 5 iterations): $median"
echo "Time to gen proof for combining all other circuits: $median"

results=()
for i in $(seq 1 5); do
   output=$($RUN_ZK_PATH --action verify --compute combine --proof-impl mirage --aux-input $CIRCUIT_2_INPUT)
   time_line=$(echo "$output" | awk 'NR==2')
   exact_time_w_unit=$(echo "$time_line" | awk '{print $5}')
   results+=("$exact_time_w_unit")
done

sorted=($(printf "%s\n" "${results[@]}" | sort -g))
median_veri1=${sorted[2]}
echo "Time to verify proof for combining all other circuits: $median_veri1"
