//! Implement edwards25519
use rug::Integer;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use rug::ops::Pow;
use rug::Complete;
use rug::integer::Order;
use std::convert::TryInto;


/// Struct for curve configuration
pub struct CurveConfig {
    /// prime modulus
    pub p: Integer,
    /// coefficient a
    pub a: Integer,
    /// coefficient d
    pub d: Integer,
    /// order of curve
    pub order: Integer,
    /// generator point
    pub generator: Edwards25519Pt,
}

/// Trait for Edwards25519 curve configuration
pub trait Ed25519Config {
    /// Create a new instance of the Edwards25519 curve configuration.
    fn new() -> CurveConfig;
}

impl Ed25519Config for CurveConfig {
    /// Create a new instance of the Edwards25519Pt curve configuration.
    fn new() -> CurveConfig {
        let generator = Edwards25519Pt {
            x: Integer::from_str_radix("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10).unwrap(),
            y: Integer::from_str_radix("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10).unwrap(),
        };
        CurveConfig {
            p: Integer::from(2).pow(255) - Integer::from(19),
            a: Integer::from(-1),
            d: Integer::from_str_radix("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10).unwrap(),
            order: Integer::from(2).pow(252) + Integer::from_str_radix("27742317777372353535851937790883648493", 10).unwrap(),
            generator: generator,
        }
    }
}

/// Struct for Edwards25519 point
#[derive(Debug, PartialEq, Clone)]
pub struct Edwards25519Pt {
    /// x-coordinate
    pub x: Integer,
    /// y-coordinate
    pub y: Integer,
}

impl Edwards25519Pt {
    /// Create a new instance of the Edwards25519Pt point.
    pub fn new(x: Integer, y: Integer) -> Edwards25519Pt {
        Edwards25519Pt {
            x,
            y,
        }
    }

    /// Check if the point is on Edwards25519 curve a*x^x + y^2 = 1 + d*x^2*y^2 
    pub fn is_on_curve(&self) -> bool {
        let ed25519 = CurveConfig::new();
        let x = &self.x;
        let y = &self.y;
        println!("{:?}", x);
        println!("{:?}", y);
        let xx = x.clone().pow_mod(&Integer::from(2), &ed25519.p).unwrap();
        let yy = y.clone().pow_mod(&Integer::from(2), &ed25519.p).unwrap();
        println!("xx {:?}", &xx);
        println!("yy {:?}", &yy);


        let lhs = ((ed25519.a.clone() * &xx + &ed25519.p) + &yy) % &ed25519.p;
        let rhs = (Integer::from(1) + (ed25519.d.clone() * &xx * &yy)) % &ed25519.p;
        println!("lhs {:?}", &lhs);
        println!("rhs {:?}", &rhs);
        lhs == rhs
    }

    /// Convert CompressedEdwardsY to Edwards25519Pt
    pub fn from_compressed(point: &CompressedEdwardsY) -> Self {
        let mut point_bytes = point.to_bytes(); 
        let x_sign: bool = (point_bytes[31] >> 7) == 1; // The last bit of a CompressedEdwardsY gives the sign of x.
        point_bytes[31] &= 0b01111111; // Clear the last bit of the y-coordinate.
        let y = Integer::from_digits(&point_bytes, Order::LsfLe); // The first 255 bits of a CompressedEdwardsY represent the y-coordinate. 
        // Decode the x-coordinate
        let ed25519 = CurveConfig::new();
        let yy: Integer = (&y * &y).complete();
        let u = (&yy - &Integer::from(1)).complete() % &ed25519.p;
        let v = (ed25519.d * &yy + &Integer::from(1)) % &ed25519.p;
        let xx = (&u * &v.invert(&ed25519.p).unwrap()).complete() % &ed25519.p; // u/v mod p
        let potential_x = xx.clone().pow_mod(&((&ed25519.p + &Integer::from(3)).complete() / &Integer::from(8)), &ed25519.p).unwrap();
        let mut x = if potential_x.clone().pow_mod(&Integer::from(2), &ed25519.p).unwrap() == xx {
            potential_x
        } else {
            (potential_x * &Integer::from(2).pow_mod(&((&ed25519.p - &Integer::from(1)).complete() / &Integer::from(4)), &ed25519.p).unwrap()) % &ed25519.p
        };
        assert!(x.clone().pow_mod(&Integer::from(2), &ed25519.p).unwrap() == xx);
        if x_sign { assert!(x != Integer::from(0)); }
        if x_sign != x.clone().is_odd() {
            x = (&ed25519.p - &x).complete()
        }
        // x.set_bytes(&point.to_bytes());
        Edwards25519Pt {
            x,
            y,
        }
    }

    /// `x` is negative if the low bit is set.
    pub fn x_is_negative(&self) -> bool {
        self.x.is_odd()
    }

    /// Convert Edwards25519Pt to CompressedEdwardsY
    pub fn compress(&self) -> CompressedEdwardsY {
        let y_bytes = self.y.to_digits(Order::LsfLe);
        // let mut x_bytes = self.x.to_digits(Order::LsfLe);
        let mut point_bytes: [u8; 32] = y_bytes.clone().try_into().expect("Expected a Vec of exactly 32 bytes");
        point_bytes[31] ^= (self.x_is_negative() as u8) << 7;
        CompressedEdwardsY(point_bytes)
    }

    /// convert to proper edwards point
    pub fn to_edwards_point(&self) -> EdwardsPoint {
        self.compress().decompress().unwrap()
    }


    /// inline add function
    pub fn add(&self, pt2: &Edwards25519Pt) -> Edwards25519Pt {
        Edwards25519Pt::point_add(&self, pt2)
    }

    /// Point addition; not optimized; just to mirror with the SNARK circuit
    pub fn point_add(pt1: &Edwards25519Pt, pt2: &Edwards25519Pt) -> Edwards25519Pt {
        let ed25519 = CurveConfig::new();
        let x1 = pt1.x.clone();
        let y1 = pt1.y.clone();
        let x2 = pt2.x.clone();
        let y2 = pt2.y.clone();
        let x1x2 = (&x1 * &x2).complete() % &ed25519.p;
        let y1y2 = (&y1 * &y2).complete() % &ed25519.p;
        let partial_denominator = (ed25519.d.clone() * &x1x2 * &y1y2) % &ed25519.p;
        let x3_numerator = ((&x1 * &y2).complete() + (&x2 * &y1).complete()) % &ed25519.p;
        let y3_numerator = (&y1y2 - &ed25519.a * &x1x2).complete() % &ed25519.p;
        let x3 = (&x3_numerator * (Integer::from(1) + &partial_denominator).invert(&ed25519.p).unwrap()) % &ed25519.p;
        let y3 = (&y3_numerator * (Integer::from(1) - &partial_denominator).invert(&ed25519.p).unwrap()) % &ed25519.p;
        Edwards25519Pt {
            x: x3,
            y: y3,
        }
    }

    /// Point double; not optimized; just to mirror with the SNARK circuit
    pub fn point_double(&self) -> Self {
        Edwards25519Pt::point_add(self, self) 
        // It seems there are no more efficient ways availabe for computing point double in SNARKs 
        // Note: In standard non-SNARK computation, more efficient approachs exist
    }

    /// Scalar multiplication; not optimized; just to mirror with the SNARK circuit
    pub fn scal_mul(&self, scalar: &Integer) -> Edwards25519Pt { // scalar is in normal order least significant bit is least significant bit
        let modp = CurveConfig::new().p.clone();
        assert!(scalar < &modp && scalar >= &Integer::from(0));
        let mut result = Edwards25519Pt {
            x: Integer::from(0),
            y: Integer::from(1),
        };
        let mut base = self.clone();
        let mut n = scalar.clone();
        while n > 0 {
            if n.is_odd() {
                result = Edwards25519Pt::point_add(&result, &base);
            }
            base = (&base.point_double()).clone();
            n >>= 1;
        }
        result
    }
}
