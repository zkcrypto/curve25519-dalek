use prelude::Vec;

use edwards::EdwardsPoint;
use scalar::Scalar;

use sp1_lib::{ed25519::Ed25519AffinePoint, utils::AffinePoint};


pub(crate) fn mul(point: &EdwardsPoint, scalar: &Scalar) -> EdwardsPoint {
    let ed_point: Ed25519AffinePoint = (*point).into();

    let a_bits = scalar.bits();
    let a_bits = a_bits.iter().map(|bit| *bit == 1).collect::<Vec<bool>>();

    // This call to multi_scalar_multiplication does not make use of the identity point in the computation.
    let res = AffinePoint::multi_scalar_multiplication(
        &a_bits,
        ed_point,
        &[false; 256],
        Ed25519AffinePoint::identity(),
    )
    .unwrap();
    res.into()
}
