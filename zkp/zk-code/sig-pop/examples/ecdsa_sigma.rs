use circ::cfg::{
    clap::{self, Parser, ValueEnum},
    CircOpt,
};
use std::path::PathBuf;

use circ::create_input;

#[cfg(feature = "bellman")]
use bls12_381::Bls12;
#[cfg(feature = "bellman")]
use circ::target::r1cs::{bellman::Bellman, mirage::Mirage, proof::ProofSystem};

#[cfg(feature = "spartan")]
use circ::ir::term::text::parse_value_map;
#[cfg(feature = "spartan")]
use circ::target::r1cs::{spartan};
use circ::ecdsa::pure_sigma::{prover, verifier};
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(name = "zk", about = "The CirC ZKP runner")]
struct Options {
    #[arg(long, default_value = "pi_sigma")]
    proof: PathBuf,
    #[arg(long)]
    action: ProofAction,
    // #[arg(long, default_value = "verify-ecdsa")]
    // compute: create_input::ComputeType,
    #[command(flatten)]
    circ: CircOpt,
}

#[derive(PartialEq, Debug, Clone, ValueEnum)]
/// `Prove`/`Verify` execute proving/verifying in bellman separately
enum ProofAction {
    Prove,
    Verify,
}

fn main() {
    env_logger::Builder::from_default_env()
        .format_level(false)
        .format_timestamp(None)
        .init();
    let opts = Options::parse();
    match opts.action {
        ProofAction::Prove => {
            prover(opts.proof)
        }
        ProofAction::Verify => {
            verifier(opts.proof)
        }
    }
}
