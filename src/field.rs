// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2019 Isis Lovecruft, Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Field arithmetic modulo \\(p = 2\^{255} - 19\\).
//!
//! The `curve25519_dalek::field` module provides a type alias
//! `curve25519_dalek::field::FieldElement` to a field element type
//! defined in the `backend` module; either `FieldElement51` or
//! `FieldElement2625`.
//!
//! Field operations defined in terms of machine
//! operations, such as field multiplication or squaring, are defined in
//! the backend implementation.
//!
//! Field operations defined in terms of other field operations, such as
//! field inversion or square roots, are defined here.

use core::cmp::{Eq, PartialEq};
use core::ops::Deref;

use subtle::ConditionallySelectable;
use subtle::ConditionallyNegatable;
use subtle::Choice;
use subtle::ConstantTimeEq;

use constants;
use backend;

#[cfg(feature = "u64_backend")]
pub use backend::serial::u64::field::*;
/// A `FieldElement` represents an element of the field
/// \\( \mathbb Z / (2\^{255} - 19)\\).
///
/// The `FieldElement` type is an alias for one of the platform-specific
/// implementations.
#[cfg(feature = "u64_backend")]
pub type FieldElement = backend::serial::u64::field::FieldElement51;

#[cfg(feature = "u32_backend")]
pub use backend::serial::u32::field::*;
/// A `FieldElement` represents an element of the field
/// \\( \mathbb Z / (2\^{255} - 19)\\).
///
/// The `FieldElement` type is an alias for one of the platform-specific
/// implementations.
#[cfg(feature = "u32_backend")]
pub type FieldElement = backend::serial::u32::field::FieldElement2625;

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for FieldElement {
    /// Test equality between two `FieldElement`s.  Since the
    /// internal representation is not canonical, the field elements
    /// are normalized to wire format before comparison.
    fn ct_eq(&self, other: &FieldElement) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

/// A cannonical representation of a field element, regardless of backend.
/// 
/// # Remarks
/// This is the same representation as the u32 backend and is suitable for
/// use with GPU acceleration.
pub struct CannonicalFieldElement(pub [u32; 10]);

impl Deref for CannonicalFieldElement {
    type Target = [u32; 10];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CannonicalFieldElement {
    fn reduce(mut z: [u64; 10]) -> Self {

        const LOW_25_BITS: u64 = (1 << 25) - 1;
        const LOW_26_BITS: u64 = (1 << 26) - 1;

        /// Carry the value from limb i = 0..8 to limb i+1
        #[inline(always)]
        fn carry(z: &mut [u64; 10], i: usize) {
            debug_assert!(i < 9);
            if i % 2 == 0 {
                // Even limbs have 26 bits
                z[i+1] += z[i] >> 26;
                z[i] &= LOW_26_BITS;
            } else {
                // Odd limbs have 25 bits
                z[i+1] += z[i] >> 25;
                z[i] &= LOW_25_BITS;
            }
        }

        // Perform two halves of the carry chain in parallel.
        carry(&mut z, 0); carry(&mut z, 4);
        carry(&mut z, 1); carry(&mut z, 5);
        carry(&mut z, 2); carry(&mut z, 6);
        carry(&mut z, 3); carry(&mut z, 7);
        // Since z[3] < 2^64, c < 2^(64-25) = 2^39,
        // so    z[4] < 2^26 + 2^39 < 2^39.0002
        carry(&mut z, 4); carry(&mut z, 8);
        // Now z[4] < 2^26
        // and z[5] < 2^25 + 2^13.0002 < 2^25.0004 (good enough)

        // Last carry has a multiplication by 19:
        z[0] += 19*(z[9] >> 25);
        z[9] &= LOW_25_BITS;

        // Since z[9] < 2^64, c < 2^(64-25) = 2^39,
        //    so z[0] + 19*c < 2^26 + 2^43.248 < 2^43.249.
        carry(&mut z, 0);
        // Now z[1] < 2^25 - 2^(43.249 - 26)
        //          < 2^25.007 (good enough)
        // and we're done.

        Self([
            z[0] as u32, z[1] as u32, z[2] as u32, z[3] as u32, z[4] as u32,
            z[5] as u32, z[6] as u32, z[7] as u32, z[8] as u32, z[9] as u32,
        ])
    }

    fn from_bytes(data: &[u8]) -> Self {
        #[inline]
        fn load3(b: &[u8]) -> u64 {
        (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16)
        }

        #[inline]
        fn load4(b: &[u8]) -> u64 {
        (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16) | ((b[3] as u64) << 24)
        }

        let mut h = [0u64;10];
        const LOW_23_BITS: u64 = (1 << 23) - 1;
        h[0] =  load4(&data[ 0..]);
        h[1] =  load3(&data[ 4..]) << 6;
        h[2] =  load3(&data[ 7..]) << 5;
        h[3] =  load3(&data[10..]) << 3;
        h[4] =  load3(&data[13..]) << 2;
        h[5] =  load4(&data[16..]);
        h[6] =  load3(&data[20..]) << 7;
        h[7] =  load3(&data[23..]) << 5;
        h[8] =  load3(&data[26..]) << 4;
        h[9] = (load3(&data[29..]) & LOW_23_BITS) << 2;

        Self::reduce(h)
    }

    fn to_bytes(&self) -> [u8; 32] {
        let inp = &self.0;
        // Reduce the value represented by `in` to the range [0,2*p)
        let mut h: [u32; 10] = Self::reduce([
            // XXX this cast is annoying
            inp[0] as u64, inp[1] as u64, inp[2] as u64, inp[3] as u64, inp[4] as u64,
            inp[5] as u64, inp[6] as u64, inp[7] as u64, inp[8] as u64, inp[9] as u64,
        ]).0;

        // Let h be the value to encode.
        //
        // Write h = pq + r with 0 <= r < p.  We want to compute r = h mod p.
        //
        // Since h < 2*p, q = 0 or 1, with q = 0 when h < p and q = 1 when h >= p.
        //
        // Notice that h >= p <==> h + 19 >= p + 19 <==> h + 19 >= 2^255.
        // Therefore q can be computed as the carry bit of h + 19.
        let mut q: u32 = (h[0] + 19) >> 26;
        q = (h[1] + q) >> 25;
        q = (h[2] + q) >> 26;
        q = (h[3] + q) >> 25;
        q = (h[4] + q) >> 26;
        q = (h[5] + q) >> 25;
        q = (h[6] + q) >> 26;
        q = (h[7] + q) >> 25;
        q = (h[8] + q) >> 26;
        q = (h[9] + q) >> 25;

        debug_assert!( q == 0 || q == 1 );

        // Now we can compute r as r = h - pq = r - (2^255-19)q = r + 19q - 2^255q

        const LOW_25_BITS: u32 = (1 << 25) - 1;
        const LOW_26_BITS: u32 = (1 << 26) - 1;

        h[0] += 19*q;

        // Now carry the result to compute r + 19q...
        h[1] += h[0] >> 26;
        h[0] = h[0] & LOW_26_BITS;
        h[2] += h[1] >> 25;
        h[1] = h[1] & LOW_25_BITS;
        h[3] += h[2] >> 26;
        h[2] = h[2] & LOW_26_BITS;
        h[4] += h[3] >> 25;
        h[3] = h[3] & LOW_25_BITS;
        h[5] += h[4] >> 26;
        h[4] = h[4] & LOW_26_BITS;
        h[6] += h[5] >> 25;
        h[5] = h[5] & LOW_25_BITS;
        h[7] += h[6] >> 26;
        h[6] = h[6] & LOW_26_BITS;
        h[8] += h[7] >> 25;
        h[7] = h[7] & LOW_25_BITS;
        h[9] += h[8] >> 26;
        h[8] = h[8] & LOW_26_BITS;

        // ... but instead of carrying the value
        // (h[9] >> 25) = q*2^255 into another limb,
        // discard it, subtracting the value from h.
        debug_assert!( (h[9] >> 25) == 0 || (h[9] >> 25) == 1);
        h[9] = h[9] & LOW_25_BITS;

        let mut s = [0u8; 32];
        s[0] = (h[0] >> 0) as u8;
        s[1] = (h[0] >> 8) as u8;
        s[2] = (h[0] >> 16) as u8;
        s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
        s[4] = (h[1] >> 6) as u8;
        s[5] = (h[1] >> 14) as u8;
        s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
        s[7] = (h[2] >> 5) as u8;
        s[8] = (h[2] >> 13) as u8;
        s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
        s[10] = (h[3] >> 3) as u8;
        s[11] = (h[3] >> 11) as u8;
        s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
        s[13] = (h[4] >> 2) as u8;
        s[14] = (h[4] >> 10) as u8;
        s[15] = (h[4] >> 18) as u8;
        s[16] = (h[5] >> 0) as u8;
        s[17] = (h[5] >> 8) as u8;
        s[18] = (h[5] >> 16) as u8;
        s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
        s[20] = (h[6] >> 7) as u8;
        s[21] = (h[6] >> 15) as u8;
        s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
        s[23] = (h[7] >> 5) as u8;
        s[24] = (h[7] >> 13) as u8;
        s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
        s[26] = (h[8] >> 4) as u8;
        s[27] = (h[8] >> 12) as u8;
        s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
        s[29] = (h[9] >> 2) as u8;
        s[30] = (h[9] >> 10) as u8;
        s[31] = (h[9] >> 18) as u8;

        // Check that high bit is cleared
        debug_assert!((s[31] & 0b1000_0000u8) == 0u8);

        s
    }

    #[cfg(feature = "u32_backend")]
    /// Creates a backend-specific field element.
    pub fn to_field(&self) -> FieldElement {
        FieldElement(self.0)
    }

    #[cfg(feature = "u64_backend")]
    /// Creates a backend-specific field element.
    pub fn to_field(&self) -> FieldElement {
        FieldElement::from_bytes(&self.to_bytes())
    }
}

impl FieldElement {
    /// Converts this field to have 10 29-bit limbs. This is the same layout
    /// used in the u32 backend and is the canonical representation for 
    /// GPU acceleration.
    /// 
    /// # Warning
    /// This function requires the given field has been reduced.
    #[cfg(feature = "u32_backend")]
    pub fn to_u29(self) -> CannonicalFieldElement {
        CannonicalFieldElement(self.0)
    }

    /// Converts this field to have 10 29-bit limbs. This is the layout
    /// used in the u32 backend and is the canonical representation for 
    /// GPU acceleration.
    ///
    /// # Warning
    /// This function requires the given field has been reduced.
    #[cfg(feature = "u64_backend")]
    pub fn to_u29(self) -> CannonicalFieldElement {
        // Convert the 52 bit limbs into 8-bit limbs
        let bytes = self.to_bytes();
        CannonicalFieldElement::from_bytes(&bytes)
    }

    /// Determine if this `FieldElement` is negative, in the sense
    /// used in the ed25519 paper: `x` is negative if the low bit is
    /// set.
    ///
    /// # Return
    ///
    /// If negative, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_negative(&self) -> Choice {
        let bytes = self.to_bytes();
        (bytes[0] & 1).into()
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Return
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        let zero = [0u8; 32];
        let bytes = self.to_bytes();

        bytes.ct_eq(&zero)
    }

    /// Compute (self^(2^250-1), self^11), used as a helper function
    /// within invert() and pow22523().
    fn pow22501(&self) -> (FieldElement, FieldElement) {
        // Instead of managing which temporary variables are used
        // for what, we define as many as we need and leave stack
        // allocation to the compiler
        //
        // Each temporary variable t_i is of the form (self)^e_i.
        // Squaring t_i corresponds to multiplying e_i by 2,
        // so the pow2k function shifts e_i left by k places.
        // Multiplying t_i and t_j corresponds to adding e_i + e_j.
        //
        // Temporary t_i                      Nonzero bits of e_i
        //
        let t0  = self.square();           // 1         e_0 = 2^1
        let t1  = t0.square().square();    // 3         e_1 = 2^3
        let t2  = self * &t1;              // 3,0       e_2 = 2^3 + 2^0
        let t3  = &t0 * &t2;               // 3,1,0
        let t4  = t3.square();             // 4,2,1
        let t5  = &t2 * &t4;               // 4,3,2,1,0
        let t6  = t5.pow2k(5);             // 9,8,7,6,5
        let t7  = &t6 * &t5;               // 9,8,7,6,5,4,3,2,1,0
        let t8  = t7.pow2k(10);            // 19..10
        let t9  = &t8 * &t7;               // 19..0
        let t10 = t9.pow2k(20);            // 39..20
        let t11 = &t10 * &t9;              // 39..0
        let t12 = t11.pow2k(10);           // 49..10
        let t13 = &t12 * &t7;              // 49..0
        let t14 = t13.pow2k(50);           // 99..50
        let t15 = &t14 * &t13;             // 99..0
        let t16 = t15.pow2k(100);          // 199..100
        let t17 = &t16 * &t15;             // 199..0
        let t18 = t17.pow2k(50);           // 249..50
        let t19 = &t18 * &t13;             // 249..0

        (t19, t3)
    }

    /// Given a slice of public `FieldElements`, replace each with its inverse.
    ///
    /// All input `FieldElements` **MUST** be nonzero.
    #[cfg(feature = "alloc")]
    pub fn batch_invert(inputs: &mut [FieldElement]) {
        // Montgomery’s Trick and Fast Implementation of Masked AES
        // Genelle, Prouff and Quisquater
        // Section 3.2

        let n = inputs.len();
        let mut scratch = vec![FieldElement::one(); n];

        // Keep an accumulator of all of the previous products
        let mut acc = FieldElement::one();

        // Pass through the input vector, recording the previous
        // products in the scratch space
        for (input, scratch) in inputs.iter().zip(scratch.iter_mut()) {
            *scratch = acc;
            acc = &acc * input;
        }

	// acc is nonzero iff all inputs are nonzero
        assert_eq!(acc.is_zero().unwrap_u8(), 0);

        // Compute the inverse of all products
        acc = acc.invert();

        // Pass through the vector backwards to compute the inverses
        // in place
        for (input, scratch) in inputs.iter_mut().rev().zip(scratch.into_iter().rev()) {
            let tmp = &acc * input;
            *input = &acc * &scratch;
            acc = tmp;
        }
    }

    /// Given a nonzero field element, compute its inverse.
    ///
    /// The inverse is computed as self^(p-2), since
    /// x^(p-2)x = x^(p-1) = 1 (mod p).
    ///
    /// This function returns zero on input zero.
    pub fn invert(&self) -> FieldElement {
        // The bits of p-2 = 2^255 -19 -2 are 11010111111...11.
        //
        //                                 nonzero bits of exponent
        let (t19, t3) = self.pow22501();   // t19: 249..0 ; t3: 3,1,0
        let t20 = t19.pow2k(5);            // 254..5
        let t21 = &t20 * &t3;              // 254..5,3,1,0

        t21
    }

    /// Raise this field element to the power (p-5)/8 = 2^252 -3.
    fn pow_p58(&self) -> FieldElement {
        // The bits of (p-5)/8 are 101111.....11.
        //
        //                                 nonzero bits of exponent
        let (t19, _) = self.pow22501();    // 249..0
        let t20 = t19.pow2k(2);            // 251..2
        let t21 = self * &t20;             // 251..2,0

        t21
    }

    /// Given `FieldElements` `u` and `v`, compute either `sqrt(u/v)`
    /// or `sqrt(i*u/v)` in constant time.
    ///
    /// This function always returns the nonnegative square root.
    ///
    /// # Return
    ///
    /// - `(Choice(1), +sqrt(u/v))  ` if `v` is nonzero and `u/v` is square;
    /// - `(Choice(1), zero)        ` if `u` is zero;
    /// - `(Choice(0), zero)        ` if `v` is zero and `u` is nonzero;
    /// - `(Choice(0), +sqrt(i*u/v))` if `u/v` is nonsquare (so `i*u/v` is square).
    ///
    pub fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
        // Using the same trick as in ed25519 decoding, we merge the
        // inversion, the square root, and the square test as follows.
        //
        // To compute sqrt(α), we can compute β = α^((p+3)/8).
        // Then β^2 = ±α, so multiplying β by sqrt(-1) if necessary
        // gives sqrt(α).
        //
        // To compute 1/sqrt(α), we observe that
        //    1/β = α^(p-1 - (p+3)/8) = α^((7p-11)/8)
        //                            = α^3 * (α^7)^((p-5)/8).
        //
        // We can therefore compute sqrt(u/v) = sqrt(u)/sqrt(v)
        // by first computing
        //    r = u^((p+3)/8) v^(p-1-(p+3)/8)
        //      = u u^((p-5)/8) v^3 (v^7)^((p-5)/8)
        //      = (uv^3) (uv^7)^((p-5)/8).
        //
        // If v is nonzero and u/v is square, then r^2 = ±u/v,
        //                                     so vr^2 = ±u.
        // If vr^2 =  u, then sqrt(u/v) = r.
        // If vr^2 = -u, then sqrt(u/v) = r*sqrt(-1).
        //
        // If v is zero, r is also zero.

        let v3 = &v.square()  * v;
        let v7 = &v3.square() * v;
        let mut r = &(u * &v3) * &(u * &v7).pow_p58();
        let check = v * &r.square();

        let i = &constants::SQRT_M1;

        let correct_sign_sqrt   = check.ct_eq(        u);
        let flipped_sign_sqrt   = check.ct_eq(     &(-u));
        let flipped_sign_sqrt_i = check.ct_eq(&(&(-u)*i));

        let r_prime = &constants::SQRT_M1 * &r;
        r.conditional_assign(&r_prime, flipped_sign_sqrt | flipped_sign_sqrt_i);

        // Choose the nonnegative square root.
        let r_is_negative = r.is_negative();
        r.conditional_negate(r_is_negative);

        let was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

        (was_nonzero_square, r)
    }

    /// Attempt to compute `sqrt(1/self)` in constant time.
    ///
    /// Convenience wrapper around `sqrt_ratio_i`.
    ///
    /// This function always returns the nonnegative square root.
    ///
    /// # Return
    ///
    /// - `(Choice(1), +sqrt(1/self))  ` if `self` is a nonzero square;
    /// - `(Choice(0), zero)           ` if `self` is zero;
    /// - `(Choice(0), +sqrt(i/self))  ` if `self` is a nonzero nonsquare;
    ///
    pub fn invsqrt(&self) -> (Choice, FieldElement) {
        FieldElement::sqrt_ratio_i(&FieldElement::one(), self)
    }
}

#[cfg(test)]
mod test {
    use field::*;
    use subtle::ConditionallyNegatable;

    /// Random element a of GF(2^255-19), from Sage
    /// a = 1070314506888354081329385823235218444233221\
    ///     2228051251926706380353716438957572
    static A_BYTES: [u8; 32] =
        [ 0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68,
          0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7, 0x03,
          0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4,
          0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3, 0xa9, 0x17];

    /// Byte representation of a**2
    static ASQ_BYTES: [u8; 32] =
        [ 0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab,
          0x24, 0x04, 0x56, 0x68, 0x07, 0x91, 0x2d, 0x5d,
          0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2,
          0x63, 0x9c, 0x12, 0xba, 0x73, 0x0b, 0xe3, 0x62];

    /// Byte representation of 1/a
    static AINV_BYTES: [u8; 32] =
        [0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a,
         0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b, 0x4d, 0x70,
         0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b,
         0x90, 0x71, 0xd8, 0xe9, 0xb6, 0x18, 0xe6, 0x30];

    /// Byte representation of a^((p-5)/8)
    static AP58_BYTES: [u8; 32] =
        [0x6a, 0x4f, 0x24, 0x89, 0x1f, 0x57, 0x60, 0x36,
         0xd0, 0xbe, 0x12, 0x3c, 0x8f, 0xf5, 0xb1, 0x59,
         0xe0, 0xf0, 0xb8, 0x1b, 0x20, 0xd2, 0xb5, 0x1f,
         0x15, 0x21, 0xf9, 0xe3, 0xe1, 0x61, 0x21, 0x55];

    #[test]
    fn a_mul_a_vs_a_squared_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let asq = FieldElement::from_bytes(&ASQ_BYTES);
        assert_eq!(asq, &a * &a);
    }

    #[test]
    fn a_square_vs_a_squared_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let asq = FieldElement::from_bytes(&ASQ_BYTES);
        assert_eq!(asq, a.square());
    }

    #[test]
    fn a_square2_vs_a_squared_constant() {
        let a = FieldElement::from_bytes(&A_BYTES);
        let asq = FieldElement::from_bytes(&ASQ_BYTES);
        assert_eq!(a.square2(), &asq+&asq);
    }

    #[test]
    fn a_invert_vs_inverse_of_a_constant() {
        let a    = FieldElement::from_bytes(&A_BYTES);
        let ainv = FieldElement::from_bytes(&AINV_BYTES);
        let should_be_inverse = a.invert();
        assert_eq!(ainv, should_be_inverse);
        assert_eq!(FieldElement::one(), &a * &should_be_inverse);
    }

    #[test]
    fn batch_invert_a_matches_nonbatched() {
        let a    = FieldElement::from_bytes(&A_BYTES);
        let ap58 = FieldElement::from_bytes(&AP58_BYTES);
        let asq  = FieldElement::from_bytes(&ASQ_BYTES);
        let ainv = FieldElement::from_bytes(&AINV_BYTES);
        let a2   = &a + &a;
        let a_list = vec![a, ap58, asq, ainv, a2];
        let mut ainv_list = a_list.clone();
        FieldElement::batch_invert(&mut ainv_list[..]);
        for i in 0..5 {
            assert_eq!(a_list[i].invert(), ainv_list[i]);
        }
    }

    #[test]
    fn sqrt_ratio_behavior() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        let i = constants::SQRT_M1;
        let two = &one + &one; // 2 is nonsquare mod p.
        let four = &two + &two; // 4 is square mod p.

        // 0/0 should return (1, 0) since u is 0
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&zero, &zero);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(sqrt, zero);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 1/0 should return (0, 0) since v is 0, u is nonzero
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&one, &zero);
        assert_eq!(choice.unwrap_u8(), 0);
        assert_eq!(sqrt, zero);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 2/1 is nonsquare, so we expect (0, sqrt(i*2))
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&two, &one);
        assert_eq!(choice.unwrap_u8(), 0);
        assert_eq!(sqrt.square(), &two * &i);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 4/1 is square, so we expect (1, sqrt(4))
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&four, &one);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(sqrt.square(), four);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 1/4 is square, so we expect (1, 1/sqrt(4))
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&one, &four);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(&sqrt.square() * &four, one);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);
    }

    #[test]
    fn a_p58_vs_ap58_constant() {
        let a    = FieldElement::from_bytes(&A_BYTES);
        let ap58 = FieldElement::from_bytes(&AP58_BYTES);
        assert_eq!(ap58, a.pow_p58());
    }

    #[test]
    fn equality() {
        let a    = FieldElement::from_bytes(&A_BYTES);
        let ainv = FieldElement::from_bytes(&AINV_BYTES);
        assert!(a == a);
        assert!(a != ainv);
    }

    /// Notice that the last element has the high bit set, which
    /// should be ignored
    static B_BYTES: [u8;32] =
        [113, 191, 169, 143,  91, 234, 121,  15,
         241, 131, 217,  36, 230, 101,  92, 234,
           8, 208, 170, 251,  97, 127,  70, 210,
          58,  23, 166,  87, 240, 169, 184, 178];

    #[test]
    fn from_bytes_highbit_is_ignored() {
        let mut cleared_bytes = B_BYTES;
        cleared_bytes[31] &= 127u8;
        let with_highbit_set    = FieldElement::from_bytes(&B_BYTES);
        let without_highbit_set = FieldElement::from_bytes(&cleared_bytes);
        assert_eq!(without_highbit_set, with_highbit_set);
    }

    #[test]
    fn conditional_negate() {
        let       one = FieldElement::one();
        let minus_one = FieldElement::minus_one();
        let mut x = one;
        x.conditional_negate(Choice::from(1));
        assert_eq!(x, minus_one);
        x.conditional_negate(Choice::from(0));
        assert_eq!(x, minus_one);
        x.conditional_negate(Choice::from(1));
        assert_eq!(x, one);
    }

    #[test]
    fn encoding_is_canonical() {
        // Encode 1 wrongly as 1 + (2^255 - 19) = 2^255 - 18
        let one_encoded_wrongly_bytes: [u8;32] = [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        // Decode to a field element
        let one = FieldElement::from_bytes(&one_encoded_wrongly_bytes);
        // .. then check that the encoding is correct
        let one_bytes = one.to_bytes();
        assert_eq!(one_bytes[0], 1);
        for i in 1..32 {
            assert_eq!(one_bytes[i], 0);
        }
    }

    #[test]
    fn batch_invert_empty() {
        FieldElement::batch_invert(&mut []);
    }

    #[test]
    fn can_convert_field_elements() {
        let a = FieldElement::from_bytes(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);

        let b = a.to_u29().to_field();

        assert_eq!(a, b);
    }
}
