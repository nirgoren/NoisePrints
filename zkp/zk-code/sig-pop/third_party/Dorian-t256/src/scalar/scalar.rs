//! This module provides an implementation of the T256's scalar field $\mathbb{F}_q$
//! where `q = 115792089210356248762697446949407573530086143415290314195533631308867097853951 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff`
//! This module is an adaptation of code from the bls12-381 crate.
//! We modify various constants (MODULUS, R, R2, etc.) to appropriate values for Curve25519 and update tests
//! We borrow the `invert` method from the curve25519-dalek crate.
//! See NOTICE.md for more details
#![allow(clippy::all)]
use core::borrow::Borrow;
use core::convert::TryFrom;
use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use hex_literal::hex;
use num_bigint_dig::{BigUint, ModInverse};

use ark_ff::biginteger::BigInteger256;
use serde::{Deserializer, de::SeqAccess, de::Visitor, Serializer};
use std::{marker::PhantomData};

/// Compute a + b + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
  let ret = (a as u128) + (b as u128) + (carry as u128);
  (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
  let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
  (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
  let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
  (ret as u64, (ret >> 64) as u64)
}

macro_rules! impl_add_binop_specify_output {
  ($lhs:ident, $rhs:ident, $output:ident) => {
    impl<'b> Add<&'b $rhs> for $lhs {
      type Output = $output;

      #[inline]
      fn add(self, rhs: &'b $rhs) -> $output {
        &self + rhs
      }
    }

    impl<'a> Add<$rhs> for &'a $lhs {
      type Output = $output;

      #[inline]
      fn add(self, rhs: $rhs) -> $output {
        self + &rhs
      }
    }

    impl Add<$rhs> for $lhs {
      type Output = $output;

      #[inline]
      fn add(self, rhs: $rhs) -> $output {
        &self + &rhs
      }
    }
  };
}

macro_rules! impl_sub_binop_specify_output {
  ($lhs:ident, $rhs:ident, $output:ident) => {
    impl<'b> Sub<&'b $rhs> for $lhs {
      type Output = $output;

      #[inline]
      fn sub(self, rhs: &'b $rhs) -> $output {
        &self - rhs
      }
    }

    impl<'a> Sub<$rhs> for &'a $lhs {
      type Output = $output;

      #[inline]
      fn sub(self, rhs: $rhs) -> $output {
        self - &rhs
      }
    }

    impl Sub<$rhs> for $lhs {
      type Output = $output;

      #[inline]
      fn sub(self, rhs: $rhs) -> $output {
        &self - &rhs
      }
    }
  };
}

macro_rules! impl_binops_additive_specify_output {
  ($lhs:ident, $rhs:ident, $output:ident) => {
    impl_add_binop_specify_output!($lhs, $rhs, $output);
    impl_sub_binop_specify_output!($lhs, $rhs, $output);
  };
}

macro_rules! impl_binops_multiplicative_mixed {
  ($lhs:ident, $rhs:ident, $output:ident) => {
    impl<'b> Mul<&'b $rhs> for $lhs {
      type Output = $output;

      #[inline]
      fn mul(self, rhs: &'b $rhs) -> $output {
        &self * rhs
      }
    }

    impl<'a> Mul<$rhs> for &'a $lhs {
      type Output = $output;

      #[inline]
      fn mul(self, rhs: $rhs) -> $output {
        self * &rhs
      }
    }

    impl Mul<$rhs> for $lhs {
      type Output = $output;

      #[inline]
      fn mul(self, rhs: $rhs) -> $output {
        &self * &rhs
      }
    }
  };
}

macro_rules! impl_binops_additive {
  ($lhs:ident, $rhs:ident) => {
    impl_binops_additive_specify_output!($lhs, $rhs, $lhs);

    impl SubAssign<$rhs> for $lhs {
      #[inline]
      fn sub_assign(&mut self, rhs: $rhs) {
        *self = &*self - &rhs;
      }
    }

    impl AddAssign<$rhs> for $lhs {
      #[inline]
      fn add_assign(&mut self, rhs: $rhs) {
        *self = &*self + &rhs;
      }
    }

    impl<'b> SubAssign<&'b $rhs> for $lhs {
      #[inline]
      fn sub_assign(&mut self, rhs: &'b $rhs) {
        *self = &*self - rhs;
      }
    }

    impl<'b> AddAssign<&'b $rhs> for $lhs {
      #[inline]
      fn add_assign(&mut self, rhs: &'b $rhs) {
        *self = &*self + rhs;
      }
    }
  };
}

macro_rules! impl_binops_multiplicative {
  ($lhs:ident, $rhs:ident) => {
    impl_binops_multiplicative_mixed!($lhs, $rhs, $lhs);

    impl MulAssign<$rhs> for $lhs {
      #[inline]
      fn mul_assign(&mut self, rhs: $rhs) {
        *self = &*self * &rhs;
      }
    }

    impl<'b> MulAssign<&'b $rhs> for $lhs {
      #[inline]
      fn mul_assign(&mut self, rhs: &'b $rhs) {
        *self = &*self * rhs;
      }
    }
  };
}

/// Represents an element of the scalar field $\mathbb{F}_q$ of the Curve25519 elliptic
/// curve construction.
// The internal representation of this type is four 64-bit unsigned
// integers in little-endian order. `Scalar` values are always in
// Montgomery form; i.e., Scalar(a) = aR mod q, with R = 2^256.
// Require 5 elements instead of 4 because adding two 
#[derive(Clone, Copy, Eq)]
pub struct Scalar(pub(crate) [u64; 5]);

impl Serialize for Scalar {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
      S: Serializer,
  {
      // Serialize only the first four elements of the array
      let slice = &self.0[..4];
      if self.0[4] != 0 {
        panic!("The last element of the Scalar array must be zero");
      }
      slice.serialize(serializer)
  }
}

impl<'de> Deserialize<'de> for Scalar {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
      D: Deserializer<'de>,
  {
    let values = Vec::<u64>::deserialize(deserializer)?;
    Ok(Self([values[0], values[1], values[2], values[3], 0]))
  }
}

impl fmt::Debug for Scalar {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let tmp = self.to_bytes();
    write!(f, "0x")?;
    for &b in tmp.iter().rev() {
      write!(f, "{:02x}", b)?;
    }
    Ok(())
  }
}

impl From<u64> for Scalar {
  fn from(val: u64) -> Scalar {
    Scalar([val, 0, 0, 0, 0]) * R2
  }
}

impl ConstantTimeEq for Scalar {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.0[0].ct_eq(&other.0[0])
      & self.0[1].ct_eq(&other.0[1])
      & self.0[2].ct_eq(&other.0[2])
      & self.0[3].ct_eq(&other.0[3])
  }
}

impl PartialEq for Scalar {
  #[inline]
  fn eq(&self, other: &Self) -> bool {
    self.ct_eq(other).unwrap_u8() == 1
  }
}

impl ConditionallySelectable for Scalar {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    Scalar([
      u64::conditional_select(&a.0[0], &b.0[0], choice),
      u64::conditional_select(&a.0[1], &b.0[1], choice),
      u64::conditional_select(&a.0[2], &b.0[2], choice),
      u64::conditional_select(&a.0[3], &b.0[3], choice),
      u64::conditional_select(&a.0[4], &b.0[4], choice),
    ])
  }
}

/// Constant representing the modulus q = 115792089210356248762697446949407573530086143415290314195533631308867097853951
const MODULUS: Scalar = Scalar([
    0xffffffffffffffff,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
    0,
]);

impl<'a> Neg for &'a Scalar {
  type Output = Scalar;

  #[inline]
  fn neg(self) -> Scalar {
    self.neg()
  }
}

impl Neg for Scalar {
  type Output = Scalar;

  #[inline]
  fn neg(self) -> Scalar {
    -&self
  }
}

impl<'a, 'b> Sub<&'b Scalar> for &'a Scalar {
  type Output = Scalar;

  #[inline]
  fn sub(self, rhs: &'b Scalar) -> Scalar {
    self.sub(rhs)
  }
}

impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
  type Output = Scalar;

  #[inline]
  fn add(self, rhs: &'b Scalar) -> Scalar {
    self.add(rhs)
  }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
  type Output = Scalar;

  #[inline]
  fn mul(self, rhs: &'b Scalar) -> Scalar {
    self.mul(rhs)
  }
}

impl_binops_additive!(Scalar, Scalar);
impl_binops_multiplicative!(Scalar, Scalar);

/// INV = -(q^{-1} mod 2^64) mod 2^64
const INV: u64 = 0x1;

const R: Scalar = Scalar([
    0x0000000000000001,
    0xffffffff00000000,
    0xffffffffffffffff,
    0x00000000fffffffe,
    0,
]);

const R2: Scalar = Scalar([
    0x0000000000000003,
    0xfffffffbffffffff,
    0xfffffffffffffffe,
    0x00000004fffffffd,
    0,
]);

/// R^3 = 2^768 mod q
const R3: Scalar = Scalar([
    0xfffffffd0000000a,
    0xffffffedfffffff7,
    0x00000005fffffffc,
    0x0000001800000001,
    0,
]);

impl Default for Scalar {
  #[inline]
  fn default() -> Self {
    Self::zero()
  }
}

impl<T> Product<T> for Scalar
where
  T: Borrow<Scalar>,
{
  fn product<I>(iter: I) -> Self
  where
    I: Iterator<Item = T>,
  {
    iter.fold(Scalar::one(), |acc, item| acc * item.borrow())
  }
}

impl<T> Sum<T> for Scalar
where
  T: Borrow<Scalar>,
{
  fn sum<I>(iter: I) -> Self
  where
    I: Iterator<Item = T>,
  {
    iter.fold(Scalar::zero(), |acc, item| acc + item.borrow())
  }
}

impl Zeroize for Scalar {
  fn zeroize(&mut self) {
    self.0 = [0u64; 5];
  }
}

impl Scalar {
  /// Returns zero, the additive identity.
  #[inline]
  pub const fn zero() -> Scalar {
    Scalar([0, 0, 0, 0, 0])
  }

  /// Returns one, the multiplicative identity.
  #[inline]
  pub const fn one() -> Scalar {
    R
  }

  pub fn random<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
    let mut limbs = [0u64; 8];
    for i in 0..8 {
      limbs[i] = rng.next_u64();
    }
    Scalar::from_u512(limbs)
  }

  /// Doubles this field element.
  #[inline]
  pub const fn double(&self) -> Scalar {
    // TODO: This can be achieved more efficiently with a bitshift.
    self.add(self)
  }

  /// Attempts to convert a little-endian byte representation of
  /// a scalar into a `Scalar`, failing if the input is not canonical.
  pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Scalar> {
    let mut tmp = Scalar([0, 0, 0, 0, 0]);

    tmp.0[0] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[..8]).unwrap());
    tmp.0[1] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
    tmp.0[2] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
    tmp.0[3] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

    // Try to subtract the modulus
    let (_, borrow) = sbb(tmp.0[0], MODULUS.0[0], 0);
    let (_, borrow) = sbb(tmp.0[1], MODULUS.0[1], borrow);
    let (_, borrow) = sbb(tmp.0[2], MODULUS.0[2], borrow);
    let (_, borrow) = sbb(tmp.0[3], MODULUS.0[3], borrow);

    // If the element is smaller than MODULUS then the
    // subtraction will underflow, producing a borrow value
    // of 0xffff...ffff. Otherwise, it'll be zero.
    let is_some = (borrow as u8) & 1;

    // Convert to Montgomery form by computing
    // (a.R^0 * R^2) / R = a.R
    tmp *= &R2;

    CtOption::new(tmp, Choice::from(is_some))
  }

  /// Converts an element of `Scalar` into a byte representation in
  /// little-endian byte order.
  pub fn to_bytes(&self) -> [u8; 32] {
    // Turn into canonical form by computing
    // (a.R) / R = a
    // let tmp = Scalar::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);
    let tmp = Scalar::montgomery_reduce(
      self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], 0, 0, 0, 0,
    );

    let mut res = [0; 32];
    res[..8].copy_from_slice(&tmp.0[0].to_le_bytes());
    res[8..16].copy_from_slice(&tmp.0[1].to_le_bytes());
    res[16..24].copy_from_slice(&tmp.0[2].to_le_bytes());
    res[24..32].copy_from_slice(&tmp.0[3].to_le_bytes());

    res
  }

  /// Converts a 512-bit little endian integer into
  /// a `Scalar` by reducing by the modulus.
  pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
    Scalar::from_u512([
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[..8]).unwrap()),
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap()),
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap()),
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap()),
      u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap()),
    ])
  }

  fn from_u512(limbs: [u64; 8]) -> Scalar {
    // We reduce an arbitrary 512-bit number by decomposing it into two 256-bit digits
    // with the higher bits multiplied by 2^256. Thus, we perform two reductions
    //
    // 1. the lower bits are multiplied by R^2, as normal
    // 2. the upper bits are multiplied by R^2 * 2^256 = R^3
    //
    // and computing their sum in the field. It remains to see that arbitrary 256-bit
    // numbers can be placed into Montgomery form safely using the reduction. The
    // reduction works so long as the product is less than R=2^256 multipled by
    // the modulus. This holds because for any `c` smaller than the modulus, we have
    // that (2^256 - 1)*c is an acceptable product for the reduction. Therefore, the
    // reduction always works so long as `c` is in the field; in this case it is either the
    // constant `R2` or `R3`.
    let d0 = Scalar([limbs[0], limbs[1], limbs[2], limbs[3], 0]);
    let d1 = Scalar([limbs[4], limbs[5], limbs[6], limbs[7], 0]);
    // Convert to Montgomery form
    d0 * R2 + d1 * R3
  }

  /// Converts from an integer represented in little endian
  /// into its (congruent) `Scalar` representation.
  pub const fn from_raw(val: [u64; 4]) -> Self {
    (&Scalar([val[0], val[1], val[2], val[3], 0])).mul(&R2)
  }

  /// Squares this element.
  #[inline]
  pub const fn square(&self) -> Scalar {
    let (r1, carry) = mac(0, self.0[0], self.0[1], 0);
    let (r2, carry) = mac(0, self.0[0], self.0[2], carry);
    let (r3, r4) = mac(0, self.0[0], self.0[3], carry);

    let (r3, carry) = mac(r3, self.0[1], self.0[2], 0);
    let (r4, r5) = mac(r4, self.0[1], self.0[3], carry);

    let (r5, r6) = mac(r5, self.0[2], self.0[3], 0);

    let r7 = r6 >> 63;
    let r6 = (r6 << 1) | (r5 >> 63);
    let r5 = (r5 << 1) | (r4 >> 63);
    let r4 = (r4 << 1) | (r3 >> 63);
    let r3 = (r3 << 1) | (r2 >> 63);
    let r2 = (r2 << 1) | (r1 >> 63);
    let r1 = r1 << 1;

    let (r0, carry) = mac(0, self.0[0], self.0[0], 0);
    let (r1, carry) = adc(0, r1, carry);
    let (r2, carry) = mac(r2, self.0[1], self.0[1], carry);
    let (r3, carry) = adc(0, r3, carry);
    let (r4, carry) = mac(r4, self.0[2], self.0[2], carry);
    let (r5, carry) = adc(0, r5, carry);
    let (r6, carry) = mac(r6, self.0[3], self.0[3], carry);
    let (r7, _) = adc(0, r7, carry);

    // Scalar::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    Scalar::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, 0)
  }

  /// Exponentiates `self` by `by`, where `by` is a
  /// little-endian order integer exponent.
  pub fn pow(&self, by: &[u64; 4]) -> Self {
    let mut res = Self::one();
    for e in by.iter().rev() {
      for i in (0..64).rev() {
        res = res.square();
        let mut tmp = res;
        tmp *= self;
        res.conditional_assign(&tmp, (((*e >> i) & 0x1) as u8).into());
      }
    }
    res
  }

  /// Exponentiates `self` by `by`, where `by` is a
  /// little-endian order integer exponent.
  ///
  /// **This operation is variable time with respect
  /// to the exponent.** If the exponent is fixed,
  /// this operation is effectively constant time.
  pub fn pow_vartime(&self, by: &[u64; 4]) -> Self {
    let mut res = Self::one();
    for e in by.iter().rev() {
      for i in (0..64).rev() {
        res = res.square();

        if ((*e >> i) & 1) == 1 {
          res.mul_assign(self);
        }
      }
    }
    res
  }

  pub fn invert(&self) -> CtOption<Self> {
    // adapt from https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/Spartan-secq/src/scalar/scalar.rs#L607
    let val = BigUint::from_bytes_le(&self.to_bytes());

    let result = val.mod_inverse(&BigUint::from_bytes_be(&hex!(
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    )));

    if result.is_some() {
        let mut result = result.unwrap().to_bytes_le().1.to_vec();
        result.resize(64, 0);
  
        let result_bytes: [u8; 64] = result.try_into().unwrap();
        let result = Scalar::from_bytes_wide(&result_bytes);
  
        CtOption::new(result, Choice::from(1))
      } else {
        CtOption::new(Scalar::zero(), Choice::from(0))
      }
  }

  pub fn batch_invert(inputs: &mut [Scalar]) -> Scalar {
    // This code is essentially identical to the FieldElement
    // implementation, and is documented there.  Unfortunately,
    // it's not easy to write it generically, since here we want
    // to use `UnpackedScalar`s internally, and `Scalar`s
    // externally, but there's no corresponding distinction for
    // field elements.

    use zeroize::Zeroizing;

    let n = inputs.len();
    let one = Scalar::one();

    // Place scratch storage in a Zeroizing wrapper to wipe it when
    // we pass out of scope.
    let scratch_vec = vec![one; n];
    let mut scratch = Zeroizing::new(scratch_vec);

    // Keep an accumulator of all of the previous products
    let mut acc = Scalar::one();

    // Pass through the input vector, recording the previous
    // products in the scratch space
    for (input, scratch) in inputs.iter().zip(scratch.iter_mut()) {
      *scratch = acc;

      acc = acc * input;
    }

    // acc is nonzero iff all inputs are nonzero
    debug_assert!(acc != Scalar::zero());

    // Compute the inverse of all products
    acc = acc.invert().unwrap();

    // We need to return the product of all inverses later
    let ret = acc;

    // Pass through the vector backwards to compute the inverses
    // in place
    for (input, scratch) in inputs.iter_mut().rev().zip(scratch.iter().rev()) {
      let tmp = &acc * input.clone();
      *input = &acc * scratch;
      acc = tmp;
    }

    ret
  }


  #[inline(always)]
  const fn montgomery_reduce(
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
    r6: u64,
    r7: u64,
    r8: u64,
  ) -> Self {
    // The Montgomery reduction here is based on Algorithm 14.32 in
    // Handbook of Applied Cryptography
    // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

    let k = r0.wrapping_mul(INV);
    let (_, carry) = mac(r0, k, MODULUS.0[0], 0);
    let (r1, carry) = mac(r1, k, MODULUS.0[1], carry);
    let (r2, carry) = mac(r2, k, MODULUS.0[2], carry);
    let (r3, carry) = mac(r3, k, MODULUS.0[3], carry);
    let (r4, carry) = mac(r4, k, MODULUS.0[4], carry);
    let (r5, carry2) = adc(r5, 0, carry);

    let k = r1.wrapping_mul(INV);
    let (_, carry) = mac(r1, k, MODULUS.0[0], 0);
    let (r2, carry) = mac(r2, k, MODULUS.0[1], carry);
    let (r3, carry) = mac(r3, k, MODULUS.0[2], carry);
    let (r4, carry) = mac(r4, k, MODULUS.0[3], carry);
    let (r5, carry) = mac(r5, k, MODULUS.0[4], carry);
    let (r6, carry2) = adc(r6, carry2, carry);

    let k = r2.wrapping_mul(INV);
    let (_, carry) = mac(r2, k, MODULUS.0[0], 0);
    let (r3, carry) = mac(r3, k, MODULUS.0[1], carry);
    let (r4, carry) = mac(r4, k, MODULUS.0[2], carry);
    let (r5, carry) = mac(r5, k, MODULUS.0[3], carry);
    let (r6, carry) = mac(r6, k, MODULUS.0[4], carry);
    let (r7, carry2) = adc(r7, carry2, carry);

    let k = r3.wrapping_mul(INV);
    let (_, carry) = mac(r3, k, MODULUS.0[0], 0);
    let (r4, carry) = mac(r4, k, MODULUS.0[1], carry);
    let (r5, carry) = mac(r5, k, MODULUS.0[2], carry);
    let (r6, carry) = mac(r6, k, MODULUS.0[3], carry);
    let (r7, carry) = mac(r7, k, MODULUS.0[4], carry);
    let (r8, _) = adc(r8, carry2, carry);

    // Result may be within MODULUS of the correct value
    (&Scalar([r4, r5, r6, r7, r8])).sub(&MODULUS)
  }

  /// Multiplies `rhs` by `self`, returning the result.
  #[inline]
  pub const fn mul(&self, rhs: &Self) -> Self {
    assert!(rhs.0[4] == 0);
    assert!(self.0[4] == 0);
    // Schoolbook multiplication

    let (r0, carry) = mac(0, self.0[0], rhs.0[0], 0);
    let (r1, carry) = mac(0, self.0[0], rhs.0[1], carry);
    let (r2, carry) = mac(0, self.0[0], rhs.0[2], carry);
    let (r3, r4) = mac(0, self.0[0], rhs.0[3], carry);

    let (r1, carry) = mac(r1, self.0[1], rhs.0[0], 0);
    let (r2, carry) = mac(r2, self.0[1], rhs.0[1], carry);
    let (r3, carry) = mac(r3, self.0[1], rhs.0[2], carry);
    let (r4, r5) = mac(r4, self.0[1], rhs.0[3], carry);

    let (r2, carry) = mac(r2, self.0[2], rhs.0[0], 0);
    let (r3, carry) = mac(r3, self.0[2], rhs.0[1], carry);
    let (r4, carry) = mac(r4, self.0[2], rhs.0[2], carry);
    let (r5, r6) = mac(r5, self.0[2], rhs.0[3], carry);

    let (r3, carry) = mac(r3, self.0[3], rhs.0[0], 0);
    let (r4, carry) = mac(r4, self.0[3], rhs.0[1], carry);
    let (r5, carry) = mac(r5, self.0[3], rhs.0[2], carry);
    let (r6, r7) = mac(r6, self.0[3], rhs.0[3], carry);


    Scalar::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, 0)
  }


  /// Subtracts `rhs` from `self`, returning the result.
  #[inline]
  pub const fn sub(&self, rhs: &Self) -> Self {
    let (d0, borrow) = sbb(self.0[0], rhs.0[0], 0);
    let (d1, borrow) = sbb(self.0[1], rhs.0[1], borrow);
    let (d2, borrow) = sbb(self.0[2], rhs.0[2], borrow);
    let (d3, borrow) = sbb(self.0[3], rhs.0[3], borrow);
    let (d4, borrow) = sbb(self.0[4], rhs.0[4], borrow);

    // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
    // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the modulus.
    let (d0, carry) = adc(d0, MODULUS.0[0] & borrow, 0);
    let (d1, carry) = adc(d1, MODULUS.0[1] & borrow, carry);
    let (d2, carry) = adc(d2, MODULUS.0[2] & borrow, carry);
    let (d3, carry) = adc(d3, MODULUS.0[3] & borrow, carry);
    let (d4, _) = adc(d4, MODULUS.0[4] & borrow, carry);

    Scalar([d0, d1, d2, d3, d4])
  }

  // /// Adds `rhs` to `self`, returning the result.
  #[inline]
  pub const fn add(&self, rhs: &Self) -> Self {
    let (d0, carry) = adc(self.0[0], rhs.0[0], 0);
    let (d1, carry) = adc(self.0[1], rhs.0[1], carry);
    let (d2, carry) = adc(self.0[2], rhs.0[2], carry);
    let (d3, carry) = adc(self.0[3], rhs.0[3], carry);
    let (d4, _) = adc(self.0[4], rhs.0[4], carry);

    // Attempt to subtract the modulus, to ensure the value
    // is smaller than the modulus.
    (&Scalar([d0, d1, d2, d3, d4])).sub(&MODULUS)
  }


  /// Negates `self`.
  #[inline]
  pub const fn neg(&self) -> Self {
    // Subtract `self` from `MODULUS` to negate. Ignore the final
    // borrow because it cannot underflow; self is guaranteed to
    // be in the field.
    let (d0, borrow) = sbb(MODULUS.0[0], self.0[0], 0);
    let (d1, borrow) = sbb(MODULUS.0[1], self.0[1], borrow);
    let (d2, borrow) = sbb(MODULUS.0[2], self.0[2], borrow);
    let (d3, borrow) = sbb(MODULUS.0[3], self.0[3], borrow);
    let (d4, _) = sbb(MODULUS.0[4], self.0[4], borrow);

    // `tmp` could be `MODULUS` if `self` was zero. Create a mask that is
    // zero if `self` was zero, and `u64::max_value()` if self was nonzero.
    // let mask = (((self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0) as u64).wrapping_sub(1);
    let mask =
      (((self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4]) == 0) as u64).wrapping_sub(1);

    Scalar([d0 & mask, d1 & mask, d2 & mask, d3 & mask, d4 & mask])
  }

  #[inline] // ** to test
  pub fn to_bigint(&self) -> BigInteger256 { // for vartime_multiscalar_mul
    let scalar_reduced = Self::montgomery_reduce(
      self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], 0, 0, 0, 0,
    );
    BigInteger256::new(scalar_reduced.0[..4].try_into().expect("Length 4 array"))
  }
}

impl<'a> From<&'a Scalar> for [u8; 32] {
  fn from(value: &'a Scalar) -> [u8; 32] {
    value.to_bytes()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use fields::t256::ScalarField;
  use ark_serialize::CanonicalDeserialize;

  #[test]
  fn test_inv() {
    // Compute -(q^{-1} mod 2^64) mod 2^64 by exponentiating
    // by totient(2**64) - 1

    let mut inv = 1u64;
    for _ in 0..63 {
      inv = inv.wrapping_mul(inv);
      inv = inv.wrapping_mul(MODULUS.0[0]);
    }
    inv = inv.wrapping_neg();

    assert_eq!(inv, INV);
  }

  #[cfg(feature = "std")]
  #[test]
  fn test_debug() {
    assert_eq!(
      format!("{:?}", Scalar::zero()),
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
      format!("{:?}", Scalar::one()),
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    let R2_format = format!("{:?}", R2);
  }

  #[test]
  fn test_equality() {
    assert_eq!(Scalar::zero(), Scalar::zero());
    assert_eq!(Scalar::one(), Scalar::one());
    assert_eq!(R2, R2);

    assert!(Scalar::zero() != Scalar::one());
    assert!(Scalar::one() != R2);
  }

  #[test]
  fn test_to_bytes() {
    assert_eq!(
      Scalar::zero().to_bytes(),
      [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
      ]
    );

    assert_eq!(
      Scalar::one().to_bytes(),
      [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
      ]
    );

    let one_bytes = Scalar::one().to_bytes();
    let scalarbytes: ScalarField = ScalarField::deserialize_compressed(&one_bytes[..]).unwrap();// ScalarField::from(1);
    assert_eq!(
      ScalarField::from(1),
      scalarbytes
    );
    let number: u64 = 18446744073709551615;
    let scalar: Scalar = Scalar::from(number);
    assert_eq!(
      ScalarField::deserialize_compressed(&scalar.to_bytes()[..]).unwrap(),
      ScalarField::from(number)
    );
    let largest_bytes = LARGEST.to_bytes();
    println!("largest bytes {:?}", largest_bytes);
  }

  #[test]
  fn test_from_bytes() {
    assert_eq!(
      Scalar::from_bytes(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
      ])
      .unwrap(),
      Scalar::zero()
    );

    assert_eq!(
      Scalar::from_bytes(&[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
      ])
      .unwrap(),
      Scalar::one()
    );

  }

  #[test]
  fn test_from_u512_zero() {
    assert_eq!(
      Scalar::zero(),
      Scalar::from_u512([
        MODULUS.0[0],
        MODULUS.0[1],
        MODULUS.0[2],
        MODULUS.0[3],
        0,
        0,
        0,
        0
      ])
    );
  }

  #[test]
  fn test_from_u512_r() {
    assert_eq!(R, Scalar::from_u512([1, 0, 0, 0, 0, 0, 0, 0]));
  }

  #[test]
  fn test_from_u512_r2() {
    assert_eq!(R2, Scalar::from_u512([0, 0, 0, 0, 1, 0, 0, 0]));
  }

  #[test]
  fn test_from_u512_max() {
    let max_u64 = 0xffffffffffffffff;
    assert_eq!(
      R3 - R,
      Scalar::from_u512([max_u64, max_u64, max_u64, max_u64, max_u64, max_u64, max_u64, max_u64])
    );
  }


  #[test]
  fn test_zero() {
    assert_eq!(Scalar::zero(), -&Scalar::zero());
    assert_eq!(Scalar::zero(), Scalar::zero() + Scalar::zero());
    assert_eq!(Scalar::zero(), Scalar::zero() - Scalar::zero());
    assert_eq!(Scalar::zero(), Scalar::zero() * Scalar::zero());
  }
// MODULUS - 1
  const LARGEST: Scalar = Scalar([
    0xfffffffffffffffe,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
    0,
  ]);

  #[test]
  fn test_addition() {
    let mut tmp = LARGEST;

    tmp += &LARGEST;


    let target = Scalar([ // LARGEST + LARGEST % MODULUS
      0xfffffffffffffffd,
      0x00000000ffffffff,
      0x0000000000000000,
      0xffffffff00000001,
      0,
    ]);
    assert_eq!(tmp, target);
    let mut tmp = LARGEST;
    tmp += &Scalar([1, 0, 0, 0, 0]);

    assert_eq!(tmp, Scalar::zero());
  }

  #[test]
  fn test_negation() {
    let tmp = -&LARGEST;

    assert_eq!(tmp, Scalar([1, 0, 0, 0, 0]));

    let tmp = -&Scalar::zero();
    assert_eq!(tmp, Scalar::zero());
    let tmp = -&Scalar([1, 0, 0, 0, 0]);
    assert_eq!(tmp, LARGEST);
  }

  #[test]
  fn test_subtraction() {
    let mut tmp = LARGEST;
    tmp -= &LARGEST;

    assert_eq!(tmp, Scalar::zero());

    let mut tmp = Scalar::zero();
    tmp -= &LARGEST;

    let mut tmp2 = MODULUS;
    tmp2 -= &LARGEST;

    assert_eq!(tmp, tmp2);
  }

  #[test]
  fn test_multiplication() {
    let mut cur = LARGEST;

    for _ in 0..100 {
      let mut tmp = cur;
      tmp *= &cur;

      let mut tmp2 = Scalar::zero();
      for b in cur
        .to_bytes()
        .iter()
        .rev()
        .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
      {
        let tmp3 = tmp2;
        tmp2.add_assign(&tmp3);

        if b {
          tmp2.add_assign(&cur);
        }
      }

      assert_eq!(tmp, tmp2);

      cur.add_assign(&LARGEST);
    }
  }

  #[test]
  fn test_squaring() {
    let mut cur = LARGEST;

    for _ in 0..100 {
      let mut tmp = cur;
      tmp = tmp.square();

      let mut tmp2 = Scalar::zero();
      for b in cur
        .to_bytes()
        .iter()
        .rev()
        .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
      {
        let tmp3 = tmp2;
        tmp2.add_assign(&tmp3);

        if b {
          tmp2.add_assign(&cur);
        }
      }

      assert_eq!(tmp, tmp2);

      cur.add_assign(&LARGEST);
    }
  }

  #[test]
  fn test_inversion() {
    assert_eq!(Scalar::zero().invert().is_none().unwrap_u8(), 1);
    assert_eq!(Scalar::one().invert().unwrap(), Scalar::one());
    assert_eq!((-&Scalar::one()).invert().unwrap(), -&Scalar::one());

    let a = Scalar::from(123);
    let result = a.invert().unwrap();

    let mut tmp = R2;

    for _ in 0..100 {
      let mut tmp2 = tmp.invert().unwrap();
      tmp2.mul_assign(&tmp);

      assert_eq!(tmp2, Scalar::one());

      tmp.add_assign(&R2);
    }
  }

  #[test]
  fn test_invert_is_pow() {
    let q_minus_2 = [
        0xfffffffffffffffd,
        0x00000000ffffffff,
        0x0000000000000000,
        0xffffffff00000001,
    ];

    let mut r1 = R;
    let mut r2 = R;
    let mut r3 = R;

    for _ in 0..100 {
      r1 = r1.invert().unwrap();
      r2 = r2.pow_vartime(&q_minus_2);
      r3 = r3.pow(&q_minus_2);

      assert_eq!(r1, r2);
      assert_eq!(r2, r3);
      // Add R so we check something different next time around
      r1.add_assign(&R);
      r2 = r1;
      r3 = r1;
    }
  }


  #[test]
  fn test_double() {
    let a = Scalar::from_raw([
      0x1fff3231233ffffd,
      0x4884b7fa00034802,
      0x998c4fefecbc4ff3,
      0x1824b159acc50562,
    ]);

    assert_eq!(a.double(), a + a);
  }
}