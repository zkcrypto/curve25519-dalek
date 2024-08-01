// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2019 Isis Lovecruft, Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>
#![allow(non_snake_case)]

use constants;
use traits::Identity;
use scalar::Scalar;
use edwards::EdwardsPoint;
use backend::serial::curve_models::{ProjectiveNielsPoint, ProjectivePoint};
use window::NafLookupTable5;
use crate::constants::ED25519_BASEPOINT_POINT;
use prelude::Vec;

#[cfg(not(all(target_os = "zkvm", target_vendor = "succinct")))]
/// Compute \\(aA + bB\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
pub fn mul(a: &Scalar, A: &EdwardsPoint, b: &Scalar) -> EdwardsPoint {
    let a_naf = a.non_adjacent_form(5);
    let b_naf = b.non_adjacent_form(8);

    // Find starting index
    let mut i: usize = 255;
    for j in (0..256).rev() {
        i = j;
        if a_naf[i] != 0 || b_naf[i] != 0 {
            break;
        }
    }

    let table_A = NafLookupTable5::<ProjectiveNielsPoint>::from(A);
    let table_B = &constants::AFFINE_ODD_MULTIPLES_OF_BASEPOINT;

    let mut r = ProjectivePoint::identity();
    loop {
        let mut t = r.double();

        if a_naf[i] > 0 {
            t = &t.to_extended() + &table_A.select(a_naf[i] as usize);
        } else if a_naf[i] < 0 {
            t = &t.to_extended() - &table_A.select(-a_naf[i] as usize);
        }

        if b_naf[i] > 0 {
            t = &t.to_extended() + &table_B.select(b_naf[i] as usize);
        } else if b_naf[i] < 0 {
            t = &t.to_extended() - &table_B.select(-b_naf[i] as usize);
        }

        r = t.to_projective();

        if i == 0 {
            break;
        }
        i -= 1;
    }

    r.to_extended()
}

#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
use sp1_lib::{ed25519::Ed25519AffinePoint, utils::AffinePoint};
#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
/// Compute \\(aA + bB\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
///
/// Accelerated with SP1's EdAdd syscall.
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
