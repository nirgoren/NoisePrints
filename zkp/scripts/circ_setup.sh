#!/bin/bash

cd ../zk-code/sig-pop
RUSTFLAGS="-A warnings" cargo build --release --example circ --features r1cs,smt,zok,spartan
RUSTFLAGS="-A warnings" cargo build --release --example run_zk --features r1cs,smt,zok,spartan
export ZSHARP_STDLIB_PATH="$PWD/third_party/ZoKrates/zokrates_stdlib/stdlib"
export PATH="$PATH:$PWD/target/release/examples"
cd -