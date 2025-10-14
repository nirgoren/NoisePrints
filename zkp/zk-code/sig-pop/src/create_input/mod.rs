//! Create prover inputs and verifier inputs

#[macro_use]
/// Define the enums and common functions
pub mod create_input;
/// File to create prover input
pub mod prover_input;
/// File to create verifier input
pub mod verifier_input;

pub use create_input::ComputeType;
pub use create_input::PfCurve;
pub use prover_input::create_prover_input;
pub use verifier_input::create_verifier_input;

