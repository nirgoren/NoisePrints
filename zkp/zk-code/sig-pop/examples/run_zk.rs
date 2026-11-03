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
use circ::target::r1cs::{spartan};



#[derive(Debug, Parser)]
#[command(name = "zk", about = "The CirC ZKP runner")]
struct Options {
    #[arg(long, default_value = "P")]
    prover_key: PathBuf,
    #[arg(long, default_value = "V")]
    verifier_key: PathBuf,
    #[arg(long, default_value = "SpartanPP")]
    pp: PathBuf,    
    #[arg(long, default_value = "pi")]
    proof: PathBuf,
    #[arg(long, default_value = "in")]
    inputs: PathBuf,
    #[arg(long, default_value = "pin")]
    pin: PathBuf,
    #[arg(long, default_value = "vin")]
    vin: PathBuf,
    #[arg(long, default_value = "groth16")]
    proof_impl: ProofImpl,
    #[arg(long)]
    action: ProofAction,
    #[arg(long, default_value = "verify-ecdsa")]
    compute: create_input::ComputeType,
    #[arg(long, default_value = "1")]
    aux_input: String,  // New field for auxiliary input
    #[arg(long, default_value = "curve25519")]
    pfcurve: create_input::PfCurve,
    #[command(flatten)]
    circ: CircOpt,
}

#[derive(PartialEq, Debug, Clone, ValueEnum)]
/// `Prove`/`Verify` execute proving/verifying in bellman separately
enum ProofAction {
    Prove,
    Verify,
}

#[derive(PartialEq, Debug, Clone, ValueEnum)]
/// Whether to use Groth16, Mirage or Spartan
enum ProofImpl {
    Groth16,
    Mirage,
    Spartan,
    Dorian,
}

fn main() {
    env_logger::Builder::from_default_env()
        .format_level(false)
        .format_timestamp(None)
        .init();
    let opts = Options::parse();
    circ::cfg::set(&opts.circ);
    match (opts.action, opts.proof_impl) {
        #[cfg(feature = "bellman")]
        (ProofAction::Prove, ProofImpl::Groth16) => {
            println!("Proving");
            let input_map = create_input::create_prover_input(opts.compute, opts.aux_input, &opts.pfcurve);
            Bellman::<Bls12>::prove_fs_outofcir(opts.prover_key, input_map, opts.proof).unwrap();
        }
        #[cfg(feature = "bellman")]
        (ProofAction::Prove, ProofImpl::Mirage) => {
            println!("Proving");
            let input_map = create_input::create_prover_input(opts.compute, opts.aux_input, &opts.pfcurve);
            Mirage::<Bls12>::prove_fs_outofcir(opts.prover_key, input_map, opts.proof).unwrap();
        }
        #[cfg(feature = "bellman")]
        (ProofAction::Verify, ProofImpl::Groth16) => {
            println!("Verifying");
            let input_map = create_input::create_verifier_input(opts.compute, opts.aux_input, &opts.pfcurve);
            assert!(
                Bellman::<Bls12>::verify_fs_outofcir(opts.verifier_key, input_map, opts.proof).unwrap(),
                "invalid proof"
            );
        }
        #[cfg(feature = "bellman")]
        (ProofAction::Verify, ProofImpl::Mirage) => {
            println!("Verifying");
            let input_map = create_input::create_verifier_input(opts.compute, opts.aux_input, &opts.pfcurve);
            assert!(
                Mirage::<Bls12>::verify_fs_outofcir(opts.verifier_key, input_map, opts.proof).unwrap(),
                "invalid proof"
            );
        }
        #[cfg(not(feature = "bellman"))]
        (ProofAction::Prove | ProofAction::Verify, ProofImpl::Groth16 | ProofImpl::Mirage) => panic!("Missing feature: bellman"),
        #[cfg(feature = "spartan")]
        (ProofAction::Prove, ProofImpl::Spartan) => {
            let prover_input_map = create_input::create_prover_input(opts.compute, opts.aux_input, &opts.pfcurve);
            println!("Spartan Proving");
            println!("len of input_map: {}", prover_input_map.len());

            spartan::spartan::prove_fs
                (opts.prover_key, opts.pp, &prover_input_map, opts.proof, &opts.pfcurve).unwrap();
        }
        #[cfg(feature = "spartan")]
        (ProofAction::Verify, ProofImpl::Spartan) => {
            let verifier_input_map = create_input::create_verifier_input(opts.compute, opts.aux_input, &opts.pfcurve);
            println!("Spartan Verifying");

            spartan::spartan::verify_fs
                (opts.verifier_key, opts.pp, &verifier_input_map, opts.proof, &opts.pfcurve).unwrap();
        }
        #[cfg(feature = "spartan")]
        (ProofAction::Prove, ProofImpl::Dorian) => {
            let prover_input_map = create_input::create_prover_input(opts.compute, opts.aux_input, &opts.pfcurve);
            println!("Spartan Proving with verifier randomness");
            println!("len of input_map: {}", prover_input_map.len());
            spartan::spartan_rand::prove_fs
                (opts.prover_key, opts.pp, &prover_input_map, opts.proof, &opts.pfcurve).unwrap();
        }
        #[cfg(feature = "spartan")]
        (ProofAction::Verify, ProofImpl::Dorian) => { 
            let verifier_input_map = create_input::create_verifier_input(opts.compute, opts.aux_input, &opts.pfcurve);
            println!("Spartan Verifying with verifier randomness");

            spartan::spartan_rand::verify_fs
                (opts.verifier_key, opts.pp, &verifier_input_map, opts.proof, &opts.pfcurve).unwrap();
        }       
        #[cfg(not(feature = "spartan"))]
        (_, ProofImpl::Spartan | ProofImpl::Dorian) => panic!("Missing feature: spartan"),
    }
}
