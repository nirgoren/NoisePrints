//! This module provides an implementation of the T256's scalar field $\mathbb{F}_q$
//! where `q = 115792089210356248762697446949407573530086143415290314195533631308867097853951 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff`
//! This module is an adaptation of code from the bls12-381 crate.
//! We modify various constants (MODULUS, R, R2, etc.) to appropriate values for Curve25519 and update tests
//! We borrow the `invert` method from the curve25519-dalek crate.
//! See NOTICE.md for more details
#![allow(clippy::all)]
use core::borrow::Borrow;
use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use ark_ff::biginteger::BigInteger256;

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
#[derive(Clone, Copy)]
// pub struct Scalar(pub(crate) [u64; 4]);
pub struct Scalar(pub(crate) crate::group::Scalar);

impl Scalar {
    /// Get a scalar from bytes that are a LE encoding of the scalar's unsigned integer
    /// representation.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Self {
        Self(Inner::decode(bytes).unwrap())
    }
}

type Inner = crate::group::Scalar;
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // let mut bytes = Vec::new();
        // bytes.copy_from_slice(&self.0.encode()[..]);
        self.0.encode().serialize(serializer)
        // bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    // ** to do
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(Self(Inner::decode(&bytes).unwrap()))
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // println!("**");
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter().rev() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Borrow<Inner> for &Scalar {
    fn borrow(&self) -> &Inner {
        &self.0
    }
}

impl Borrow<Inner> for Scalar {
    fn borrow(&self) -> &Inner {
        &self.0
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Scalar {
        Scalar(Inner::from_u64(val))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from(!(self.0.equals(other.0) != 0) as u8)
    }
}

impl PartialEq for Scalar {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.equals(other.0) != 0
    }
}
impl Eq for Scalar {}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        if choice.unwrap_u8() != 0 {
            *a
        } else {
            *b
        }
    }
}

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
        self.0 = Inner::ZERO;
    }
}

impl Scalar {
    /// Returns zero, the additive identity.
    #[inline]
    pub const fn zero() -> Scalar {
        Scalar(Inner::ZERO)
    }

    /// Returns one, the multiplicative identity.
    #[inline]
    pub const fn one() -> Scalar {
        Scalar(Inner::ONE)
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
    pub fn double(&self) -> Scalar {
        // TODO: This can be achieved more efficiently with a bitshift.
        self.add(self)
    }

    /// Attempts to convert a little-endian byte representation of
    /// a scalar into a `Scalar`, failing if the input is not canonical.
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Scalar> {
        if let Some(b) = Inner::decode(bytes) {
            CtOption::new(Scalar(b), Choice::from(1))
        } else {
            CtOption::new(Scalar(Inner::ZERO), Choice::from(0))
        }
    }

    /// Converts an element of `Scalar` into a byte representation in
    /// little-endian byte order.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.encode()
    }

    /// Converts a 512-bit little endian integer into
    /// a `Scalar` by reducing by the modulus.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        Self(Inner::decode_reduce(bytes))
    }

    fn from_u512(limbs: [u64; 8]) -> Scalar {
        let mut bytes = [0u8; 64];
        for i in 0..8 {
            bytes[8 * i..8 * i + 8].copy_from_slice(&limbs[i].to_le_bytes()[..]);
        }
        Self::from_bytes_wide(&bytes)
    }

    /// Converts from an integer represented in little endian
    /// into its (congruent) `Scalar` representation.
    pub fn from_raw(_val: [u64; 4]) -> Self {
        todo!()
    }

    /// Squares this element.
    #[inline]
    pub fn square(&self) -> Scalar {
        Scalar(self.0.square())
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
        if self.0.iszero() == 0 {
            CtOption::new(Scalar(Inner::ONE / self.0), Choice::from(1))
        } else {
            CtOption::new(Scalar(Inner::ONE), Choice::from(0))
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

    /// Multiplies `rhs` by `self`, returning the result.
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }

    /// Subtracts `rhs` from `self`, returning the result.
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }

    // /// Adds `rhs` to `self`, returning the result.
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }

    /// Negates `self`.
    #[inline]
    pub fn neg(&self) -> Self {
        Self(-self.0)
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
    use ark_serialize::CanonicalDeserialize;

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
    }

    #[test]
    fn test_equality() {
        assert_eq!(Scalar::zero(), Scalar::zero());
        assert_eq!(Scalar::one(), Scalar::one());

        assert!(Scalar::zero() != Scalar::one());
    }


    #[test]
    fn test_from_bytes() {
        assert_eq!(
            Scalar::from_bytes(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ])
            .unwrap(),
            Scalar::zero()
        );

        assert_eq!(
            Scalar::from_bytes(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ])
            .unwrap(),
            Scalar::one()
        );

        // assert_eq!(
        //   Scalar::from_bytes(&[
        //     29, 149, 152, 141, 116, 49, 236, 214, 112, 207, 125, 115, 244, 91, 239, 198, 254, 255, 255,
        //     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 15
        //   ])
        //   .unwrap(),
        //   R2
        // );

        // // -1 should work
        // assert!(
        //   Scalar::from_bytes(&[
        //     236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0,
        //     0, 0, 0, 0, 0, 0, 0, 0, 0, 16
        //   ])
        //   .is_some()
        //   .unwrap_u8()
        //     == 1
        // );

        // // modulus is invalid
        // assert!(
        //   Scalar::from_bytes(&[
        //     1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8, 216,
        //     57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        //   ])
        //   .is_none()
        //   .unwrap_u8()
        //     == 1
        // );

        // // Anything larger than the modulus is invalid
        // assert!(
        //   Scalar::from_bytes(&[
        //     2, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8, 216,
        //     57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        //   ])
        //   .is_none()
        //   .unwrap_u8()
        //     == 1
        // );
        // assert!(
        //   Scalar::from_bytes(&[
        //     1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8, 216,
        //     58, 51, 72, 125, 157, 41, 83, 167, 237, 115
        //   ])
        //   .is_none()
        //   .unwrap_u8()
        //     == 1
        // );
        // assert!(
        //   Scalar::from_bytes(&[
        //     1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8, 216,
        //     57, 51, 72, 125, 157, 41, 83, 167, 237, 116
        //   ])
        //   .is_none()
        //   .unwrap_u8()
        //     == 1
        // );
    }

    //   #[test]
    //   fn test_from_bytes_wide_r2() {
    //     assert_eq!(
    //       R2,
    //       Scalar::from_bytes_wide(&[
    //         29, 149, 152, 141, 116, 49, 236, 214, 112, 207, 125, 115, 244, 91, 239, 198, 254, 255, 255,
    //         255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //       ])
    //     );
    //   }

    //   #[test]
    //   fn test_from_bytes_wide_negative_one() {
    //     assert_eq!(
    //       -&Scalar::one(),
    //       Scalar::from_bytes_wide(&[
    //         236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0,
    //         0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //       ])
    //     );
    //   }

    // #[test]
    // fn test_from_bytes_wide_maximum() {
    //   assert_eq!(
    //     Scalar::from_raw([
    //       0xa40611e3449c0f00,
    //       0xd00e1ba768859347,
    //       0xceec73d217f5be65,
    //       0x0399411b7c309a3d
    //     ]),
    //     Scalar::from_bytes_wide(&[0xff; 64])
    //   );
    // }

    #[test]
    fn test_zero() {
        assert_eq!(Scalar::zero(), -&Scalar::zero());
        assert_eq!(Scalar::zero(), Scalar::zero() + Scalar::zero());
        assert_eq!(Scalar::zero(), Scalar::zero() - Scalar::zero());
        assert_eq!(Scalar::zero(), Scalar::zero() * Scalar::zero());
    }

    //   const LARGEST: Scalar = Scalar([
    //     0x5812631a5cf5d3ec,
    //     0x14def9dea2f79cd6,
    //     0x0000000000000000,
    //     0x1000000000000000,
    //   ]);
    // MODULUS - 1
    const LARGEST: Scalar = Scalar(Inner::MINUS_ONE);

    #[test]
    fn test_addition() {
        let mut tmp = LARGEST;

        tmp += &LARGEST;

        let target = Scalar(Inner::ONE.mul2().neg());
        assert_eq!(tmp, target);
        let mut tmp = LARGEST;
        tmp += &Scalar::from(1);

        assert_eq!(tmp, Scalar::zero());
    }

    #[test]
    fn test_negation() {
        let tmp = -&LARGEST;

        assert_eq!(tmp, Scalar::from(1));

        let tmp = -&Scalar::zero();
        assert_eq!(tmp, Scalar::zero());
        let tmp = -&Scalar::from(1);
        assert_eq!(tmp, LARGEST);
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
}
