use core::convert::TryInto;

use sp1_lib::{ed25519::Ed25519AffinePoint, utils::AffinePoint};

use crate::{edwards::EdwardsPoint, field::FieldElement};

impl From<EdwardsPoint> for Ed25519AffinePoint {
    fn from(value: EdwardsPoint) -> Self {
        let mut limbs = [0u32; 16];

        // Ensure that the point is normalized.
        assert_eq!(value.Z, FieldElement::one());

        // Convert the x and y coordinates to little endian u32 limbs.
        for (x_limb, x_bytes) in limbs[..8]
            .iter_mut()
            .zip(value.X.to_bytes().chunks_exact(4))
        {
            *x_limb = u32::from_le_bytes(x_bytes.try_into().unwrap());
        }
        for (y_limb, y_bytes) in limbs[8..]
            .iter_mut()
            .zip(value.Y.to_bytes().chunks_exact(4))
        {
            *y_limb = u32::from_le_bytes(y_bytes.try_into().unwrap());
        }

        Self { 0: limbs }
    }
}

impl From<Ed25519AffinePoint> for EdwardsPoint {
    fn from(value: Ed25519AffinePoint) -> Self {
        let le_bytes = value.to_le_bytes();
        let x = FieldElement::from_bytes(&le_bytes[..32].try_into().unwrap());
        let y = FieldElement::from_bytes(&le_bytes[32..].try_into().unwrap());
        let t = &x * &y;

        Self { X: x, Y: y, Z: FieldElement::one(), T: t }
    }
}