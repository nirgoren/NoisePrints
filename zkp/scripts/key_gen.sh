#!/bin/bash

cd ../zk-code/zkp/circuit1
./../../sig-pop/target/release/examples/circ --ram true ./dot_prod_mag.zok r1cs --action setup --proof-impl mirage > constraints.txt

cd ../circuit2
./../../sig-pop/target/release/examples/circ --ram true ./combine.zok r1cs --action setup --proof-impl mirage > constraints.txt

cd ../../../scripts