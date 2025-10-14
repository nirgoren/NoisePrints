use super::commitments::{Commitments, MultiCommitGens};
use super::group::GroupElement;
use super::scalar::{Scalar, ScalarFromPrimitives};
use super::transcript::{AppendToTranscript, ProofTranscript};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

// ax^2 + bx + c stored as vec![c,b,a]
// ax^3 + bx^2 + cx + d stored as vec![d,c,b,a]
// ax^4 + bx^3 + cx^2 + dx + e stored as vec![e,d,c,b,a]
#[derive(Debug)]
pub struct UniPoly {
  coeffs: Vec<Scalar>,
}

// ax^2 + bx + c stored as vec![c,a]
// ax^3 + bx^2 + cx + d stored as vec![d,b,a]
#[derive(Serialize, Deserialize, Debug)]
pub struct CompressedUniPoly {
  coeffs_except_linear_term: Vec<Scalar>,
}

impl UniPoly {
  pub fn from_evals(evals: &[Scalar]) -> Self {
    // // we only support degree-2 or degree-3 or degree-4 univariate polynomials
    // assert!(evals.len() == 3 || evals.len() == 4);
    let coeffs = match evals.len() {
      3 => {
        // ax^2 + bx + c
        let two_inv = (2_usize).to_scalar().invert().unwrap();

        let c = evals[0];
        let a = two_inv * (evals[2] - evals[1] - evals[1] + c);
        let b = evals[1] - c - a;
        vec![c, b, a]
      },
      4 => {
        // ax^3 + bx^2 + cx + d
        let two_inv = (2_usize).to_scalar().invert().unwrap();
        let six_inv = (6_usize).to_scalar().invert().unwrap();

        let d = evals[0];
        let a = six_inv
          * (evals[3] - evals[2] - evals[2] - evals[2] + evals[1] + evals[1] + evals[1] - evals[0]);
        let b = two_inv
          * (evals[0] + evals[0] - evals[1] - evals[1] - evals[1] - evals[1] - evals[1]
            + evals[2]
            + evals[2]
            + evals[2]
            + evals[2]
            - evals[3]);
        let c = evals[1] - d - a - b;
        vec![d, c, b, a]
      },
      5 => {
        // ax^4 + bx^3 + cx^2 + dx + e
        let e = evals[0];

        let four_inv = (24_usize).to_scalar().invert().unwrap(); // Invert of 4 factorial for quartic term
        let a = four_inv * 
          (evals[4] - (4_usize).to_scalar() * evals[3] + (6_usize).to_scalar() * evals[2] - (4_usize).to_scalar() * evals[1] + e);
        println!("a: {:?}", a);
        let twelve_inv = (12_usize).to_scalar().invert().unwrap(); // Invert of 3 factorial for cubic term
        let b = twelve_inv * 
          (-(3_usize).to_scalar() * evals[4] + (14_usize).to_scalar() * evals[3] - (24_usize).to_scalar() * evals[2] + (18_usize).to_scalar() * evals[1] - (5_usize).to_scalar() * e); 
        println!("b: {:?}", b);

        let twenty_four_inv = (24_usize).to_scalar().invert().unwrap(); // Invert of 2 factorial for quadratic term
        let c = twenty_four_inv * 
          ((11_usize).to_scalar() * evals[4] - (56_usize).to_scalar() * evals[3] + (114_usize).to_scalar() * evals[2] - (104_usize).to_scalar() * evals[1] + (35_usize).to_scalar() * e); 
        
        let d = evals[1] - e - c - b - a;
        vec![e, d, c, b, a]
      },
      _ => panic!("Unsupported degree of polynomial"),
    };


    UniPoly { coeffs }
  }

  pub fn degree(&self) -> usize {
    self.coeffs.len() - 1
  }

  pub fn as_vec(&self) -> Vec<Scalar> {
    self.coeffs.clone()
  }

  pub fn eval_at_zero(&self) -> Scalar {
    self.coeffs[0]
  }

  pub fn eval_at_one(&self) -> Scalar {
    (0..self.coeffs.len()).map(|i| self.coeffs[i]).sum()
  }

  pub fn evaluate(&self, r: &Scalar) -> Scalar {
    let mut eval = self.coeffs[0];
    let mut power = *r;
    for i in 1..self.coeffs.len() {
      eval += power * self.coeffs[i];
      power *= r;
    }
    eval
  }

  pub fn compress(&self) -> CompressedUniPoly {
    let coeffs_except_linear_term = [&self.coeffs[..1], &self.coeffs[2..]].concat();
    assert_eq!(coeffs_except_linear_term.len() + 1, self.coeffs.len());
    CompressedUniPoly {
      coeffs_except_linear_term,
    }
  }

  pub fn commit(&self, gens: &MultiCommitGens, blind: &Scalar) -> GroupElement {
    self.coeffs.commit(blind, gens)
  }
}

impl CompressedUniPoly {
  // we require eval(0) + eval(1) = hint, so we can solve for the linear term as:
  // linear_term = hint - 2 * constant_term - deg2 term - deg3 term
  pub fn decompress(&self, hint: &Scalar) -> UniPoly {
    let mut linear_term =
      hint - self.coeffs_except_linear_term[0] - self.coeffs_except_linear_term[0];
    for i in 1..self.coeffs_except_linear_term.len() {
      linear_term -= self.coeffs_except_linear_term[i];
    }

    let mut coeffs = vec![self.coeffs_except_linear_term[0], linear_term];
    coeffs.extend(&self.coeffs_except_linear_term[1..]);
    assert_eq!(self.coeffs_except_linear_term.len() + 1, coeffs.len());
    UniPoly { coeffs }
  }
}

impl AppendToTranscript for UniPoly {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"UniPoly_begin");
    for i in 0..self.coeffs.len() {
      transcript.append_scalar(b"coeff", &self.coeffs[i]);
    }
    transcript.append_message(label, b"UniPoly_end");
  }
}

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn test_from_evals_quad() {
    // polynomial is 2x^2 + 3x + 1
    let e0 = Scalar::one();
    let e1 = (6_usize).to_scalar();
    let e2 = (15_usize).to_scalar();
    let evals = vec![e0, e1, e2];
    let poly = UniPoly::from_evals(&evals);

    assert_eq!(poly.eval_at_zero(), e0);
    assert_eq!(poly.eval_at_one(), e1);
    assert_eq!(poly.coeffs.len(), 3);
    assert_eq!(poly.coeffs[0], Scalar::one());
    assert_eq!(poly.coeffs[1], (3_usize).to_scalar());
    assert_eq!(poly.coeffs[2], (2_usize).to_scalar());

    let hint = e0 + e1;
    let compressed_poly = poly.compress();
    let decompressed_poly = compressed_poly.decompress(&hint);
    for i in 0..decompressed_poly.coeffs.len() {
      assert_eq!(decompressed_poly.coeffs[i], poly.coeffs[i]);
    }

    let e3 = (28_usize).to_scalar();
    assert_eq!(poly.evaluate(&(3_usize).to_scalar()), e3);
  }

  #[test]
  fn test_from_evals_cubic() {
    // polynomial is x^3 + 2x^2 + 3x + 1
    let e0 = Scalar::one();
    let e1 = (7_usize).to_scalar();
    let e2 = (23_usize).to_scalar();
    let e3 = (55_usize).to_scalar();
    let evals = vec![e0, e1, e2, e3];
    let poly = UniPoly::from_evals(&evals);

    assert_eq!(poly.eval_at_zero(), e0);
    assert_eq!(poly.eval_at_one(), e1);
    assert_eq!(poly.coeffs.len(), 4);
    assert_eq!(poly.coeffs[0], Scalar::one());
    assert_eq!(poly.coeffs[1], (3_usize).to_scalar());
    assert_eq!(poly.coeffs[2], (2_usize).to_scalar());
    assert_eq!(poly.coeffs[3], (1_usize).to_scalar());

    let hint = e0 + e1;
    let compressed_poly = poly.compress();
    let decompressed_poly = compressed_poly.decompress(&hint);
    for i in 0..decompressed_poly.coeffs.len() {
      assert_eq!(decompressed_poly.coeffs[i], poly.coeffs[i]);
    }

    let e4 = (109_usize).to_scalar();
    assert_eq!(poly.evaluate(&(4_usize).to_scalar()), e4);
  }

  #[test]
  fn test_from_evals_quartic() {
      // Polynomial is x^4 + 2x^3 + 3x^2 + 4x + 5
      let e0 = (5_usize).to_scalar();
      let e1 = (15_usize).to_scalar();
      let e2 = (57_usize).to_scalar();
      let e3 = (179_usize).to_scalar();
      let e4 = (453_usize).to_scalar();
      let evals = vec![e0, e1, e2, e3, e4];
      let poly = UniPoly::from_evals(&evals);
      assert_eq!(poly.coeffs, vec![(5_usize).to_scalar(), 
        (4_usize).to_scalar(), 
        (3_usize).to_scalar(), 
        (2_usize).to_scalar(), 
        (1_usize).to_scalar()]
      );

      // Polynomial is 7x^4 + 2x^3 + 3x^2 + 4x + 5
      let e0 = (5_usize).to_scalar();
      let e1 = (21_usize).to_scalar();
      let e2 = (153_usize).to_scalar();
      let e3 = (665_usize).to_scalar();
      let e4 = (1989_usize).to_scalar();
      let evals = vec![e0, e1, e2, e3, e4];
      let poly = UniPoly::from_evals(&evals);
      assert_eq!(poly.coeffs, vec![(5_usize).to_scalar(), 
        (4_usize).to_scalar(), 
        (3_usize).to_scalar(), 
        (2_usize).to_scalar(), 
        (7_usize).to_scalar()]
      );

      assert_eq!(poly.eval_at_zero(), e0);
      assert_eq!(poly.eval_at_one(), e1);
      assert_eq!(poly.coeffs.len(), 5);

    //   assert_eq!(poly.coeffs, vec![(5_usize).to_scalar(), 
    //     (4_usize).to_scalar(), 
    //     (3_usize).to_scalar(), 
    //     (2_usize).to_scalar(), 
    //     (1_usize).to_scalar()]
    // );

  }
}
