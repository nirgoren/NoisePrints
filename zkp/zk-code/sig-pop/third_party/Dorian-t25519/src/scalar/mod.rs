mod scalar;

pub type Scalar = scalar::Scalar;

pub trait ScalarFromPrimitives {
  fn to_scalar(self) -> Scalar;
}

impl ScalarFromPrimitives for usize {
  #[inline]
  fn to_scalar(self) -> Scalar {
    (0..self).map(|_i| Scalar::one()).sum()
  }
}

impl ScalarFromPrimitives for bool {
  #[inline]
  fn to_scalar(self) -> Scalar {
    if self {
      Scalar::one()
    } else {
      Scalar::zero()
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_decompress_scalar() {
    for i in 0..50000 {
      let _scalars = vec![Scalar::from(i+1), Scalar::from(i+2), Scalar::from(i+3), Scalar::from(i+4), Scalar::from(i+5), Scalar::from(i+6), Scalar::from(i+7), Scalar::from(i+8), Scalar::from(i+9), Scalar::from(i+10)];

      //let result = Scalar::decompress_vector(&scalars);
      // let result_v2 = Scalar::decompress_vector_v2(&scalars);
      // println!("result {:?}", result);
      // assert!(result == result_v2);
    }
  }

}
