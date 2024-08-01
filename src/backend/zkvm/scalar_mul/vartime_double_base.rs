use edwards::EdwardsPoint;
use prelude::Vec;
use scalar::Scalar;
use sp1_lib::{ed25519::Ed25519AffinePoint, utils::AffinePoint};

use crate::backend::serial::u64::constants::ED25519_BASEPOINT_POINT;

/// Compute \\(aA + bB\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
#[allow(non_snake_case)]
pub fn mul(a: &Scalar, A: &EdwardsPoint, b: &Scalar) -> EdwardsPoint {
    let A: Ed25519AffinePoint = (*A).into();

    let a_bits = a.bits();
    let a_bits = a_bits.iter().map(|bit| *bit == 1).collect::<Vec<bool>>();
    let b_bits = b.bits();
    let b_bits = b_bits.iter().map(|bit| *bit == 1).collect::<Vec<bool>>();

    // Note: The base point is the identity point.
    let res = AffinePoint::multi_scalar_multiplication(
        &a_bits,
        A,
        &b_bits,
        ED25519_BASEPOINT_POINT.into(),
    )
    .unwrap();
    res.into()
}
