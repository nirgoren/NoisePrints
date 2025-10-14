#[macro_export]
#[doc(hidden)]
macro_rules! __derive_conversion {
    ($config: ty, $dim: expr, $sec_param: expr, $OtherCurve: ty, $G2_X: ident, $G2_Y: ident, $fr: ty, $fr_config: ty, $other_q: ty, $other_r: ty, $other_q_conf: ty, $other_r_conf: ty, $affine: ty, $GSX: expr, $GSY: expr) => {
        // Define the conversion functions for this particular
        // mapping.
        type OtherBaseField = <$OtherCurve as CurveConfig>::BaseField;
        type OtherScalarField = <$OtherCurve as CurveConfig>::ScalarField;

        struct FrStruct($fr);
        impl FrStruct {
            pub fn new(x: $fr) -> FrStruct {
                FrStruct(x)
            }

        }

        impl From<BigInt<$dim>> for FrStruct {
            fn from(x: BigInt<$dim>) -> Self {
                let x_t = <$fr_config>::from_bigint(x).unwrap();
                FrStruct::new(x_t)
            }
        }

        impl From<FrStruct> for BigInt<$dim> {
            fn from(val: FrStruct) -> Self {
                FrConfig::into_bigint(val.0)
            }
        }

        struct OtherBase(OtherBaseField);
        impl OtherBase {
            pub fn new(x: $other_q) -> OtherBase {
                OtherBase(x)
            }
        }

        impl From<OtherBase> for BigInt<$dim> {
            fn from(x: OtherBase) -> Self {
                <$other_q_conf>::into_bigint(x.0)
            }
        }

        impl From<BigInt<$dim>> for OtherBase {
            fn from(x: BigInt<$dim>) -> OtherBase {
                let x_t = <$other_q_conf>::from_bigint(x).unwrap();
                OtherBase::new(x_t)
            }
        }

        struct OtherScalar(OtherScalarField);
        impl OtherScalar {
            pub fn new(x: $other_r) -> OtherScalar {
                OtherScalar(x)
            }

        }

        impl From<OtherScalar> for BigInt<$dim> {
            fn from(x: OtherScalar) -> Self {
                <$other_r_conf>::into_bigint(x.0)
            }
        }

        impl From<BigInt<$dim>> for OtherScalar {
            fn from(x: BigInt<$dim>) -> OtherScalar {
                let x_t = <$other_r_conf>::from_bigint(x).unwrap();
                OtherScalar::new(x_t)
            }
        }

    };
}

#[macro_export]
/// derive_conversion
macro_rules! derive_conversion {
    ($config: ty, $dim: expr, $sec_param: expr, $OtherCurve: ty, $G2_X: ident, $G2_Y: ident, $fr: ty, $fr_config: ty, $other_q: ty, $other_r: ty, $other_q_conf: ty, $other_r_conf: ty, $affine: ty, $GSX: expr, $GSY: expr) => {
        use ark_ff::BigInt;
        use ark_ff::{Field, MontConfig, MontFp};

        $crate::__derive_conversion!(
            $config,
            $dim,
            $sec_param,
            $OtherCurve,
            $G2_X,
            $G2_Y,
            $fr,
            $fr_config,
            $other_q,
            $other_r,
            $other_q_conf,
            $other_r_conf,
            $affine,
            $GSX,
            $GSY
        );
    };
}
