//! This module includes implementations related to Fiat-Shamir Transform

use merlin::Transcript;
use p256::ProjectivePoint;
use p256::elliptic_curve::{group::GroupEncoding};
// use serde::{Serialize, Serializer, Deserialize, Deserializer};

/// Number of bytes in the challenge space
pub const CHALLENGE_SIZE: usize = 32;



  
/// Trait for a transcript for sigma protocol
pub trait SigmaTranscript {
    /// Append a point to the transcript.
    fn append_point(&mut self, label: &'static [u8], point: &ProjectivePoint);
    /// Produce the challenge.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE];
}

impl SigmaTranscript for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &ProjectivePoint) {
        self.append_message(label, point.to_bytes().as_slice()); 
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; CHALLENGE_SIZE];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}