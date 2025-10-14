use rug::Integer;
use std::sync::Arc;
use lazy_static::lazy_static;


lazy_static! {
    /// modulus defining scalar field of T256
    pub static ref MOD_T256: Integer = Integer::from_str_radix("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap();
    // pub static ref MOD_T256: Integer = Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap();
    /// Ark modulus for T256
    pub static ref ARC_MOD_T256: Arc<Integer> = Arc::new(MOD_T256.clone());
    /// modulus defining scalar field of Secq256k1
    pub static ref MOD_SECQ256K1: Integer = Integer::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
    /// Ark modulus for Secq256k1
    pub static ref ARC_MOD_SECQ256K1: Arc<Integer> = Arc::new(MOD_SECQ256K1.clone());
    /// modulus defining scalar field of curve25519
    pub static ref MOD_CURVE25519: Integer = Integer::from_str_radix("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10).unwrap();
    /// Ark modulus for curve25519
    pub static ref ARC_MOD_CURVE25519: Arc<Integer> = Arc::new(MOD_CURVE25519.clone());
    /// modulus defining scalar field of T25519
    pub static ref MOD_T25519: Integer = Integer::from_str_radix("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10).unwrap();
    /// Ark modulus for T25519
    pub static ref ARC_MOD_T25519: Arc<Integer> = Arc::new(MOD_T25519.clone());
}