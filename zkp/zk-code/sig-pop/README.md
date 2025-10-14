# Sig-PoP
This repository contains implementations of proofs of posession for ECDSA, Ed25519, RSA, as well as standalone implementations of SHA512 and SHA256.

For more information, see our [paper](https://eprint.iacr.org/2025/538).


## Examples
#### SHA256 (|m| = 2KB)
    cargo run --release --example circ -- zok_src/test/hashes/sha256/test_sha256_adv32.zok r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute sha256-adv --aux-input 32 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute sha256-adv --aux-input 32 --proof-impl mirage --action verify

#### RSA-PKCS1v1.5 PoP (dynamic modulus, |m| = 64B)
    cargo run --release --example circ -- zok_src/test/modexpon/test_rsa2048_w_hash_advanced1.zok  r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute verify-rsa-adv-whole --aux-input 1 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute verify-rsa-adv-whole --aux-input 1 --proof-impl mirage --action verify

#### ECDSA-P256-SHA256 PoP, sidecar approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/test/ecdsa/advanced_incomplete/test_sigma_32_6_w_hash1.zok r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute verify-ecdsa-sigma-whole --aux-input 1 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute verify-ecdsa-sigma-whole --aux-input 1 --proof-impl mirage --action verify

#### ECDSA-P256-SHA256 PoP, right field approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/test/ecdsa/Fp/test_naive_32_w_hash1.zok  r1cs --action setup --proof-impl dorian --pfcurve t256
    cargo run --release --example run_zk -- --compute verify-ecdsa-right-whole --aux-input 1 --proof-impl dorian --pfcurve t256 --action prove
    cargo run --release --example run_zk -- --compute verify-ecdsa-right-whole --aux-input 1 --proof-impl dorian --pfcurve t256 --action verify

#### Ed25519 PoP, sidecar approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/ed25519/unsafe_witness/sidecar/verify1.zok  r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute eddsa-sigma --aux-input 1 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute eddsa-sigma --aux-input 1 --proof-impl mirage --action verify

#### Ed25519 PoP, right field approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/ed25519/right_field/verify1.zok r1cs --action setup --proof-impl dorian --pfcurve t25519
    cargo run --release --example zk -- --inputs zok_src/ed25519/right_field/test_verify_64.zok.pin --action prove --proof-impl dorian --pfcurve t25519
    cargo run --release --example zk -- --inputs zok_src/ed25519/right_field/test_verify_64.zok.vin --action verify --proof-impl dorian --pfcurve t25519

## NOTES:

Currently both the SHA256 and SHA512 implementations are restricted to certain message lengths. They each essentially currently require that the length of the message in bytes is a multiple of 4 and 8 respectively. Consequently, our proofs of posession have the same restriction at present. We plan on fixing this soon.
