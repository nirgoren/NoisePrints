/// Representations of intermediate values for verifying point double over P256 curve
#[derive(Clone, PartialEq, Eq)]
pub struct BigNatPointAdd_v2 {
    /// Products
    pub products: Vec<BigNatWithLimbMax>,
    /// Intermediate values
    pub remainders: Vec<BigNatbWithLimbMax>,
    /// Intermediate for modulation
    pub intermediate_mod: Vec<BigNatModWithLimbMax>,
    /// resultant point
    pub res_point: P256Point,
}