use core::borrow::Borrow;
use edwards::EdwardsPoint;
use scalar::Scalar;
use traits::VartimePrecomputedMultiscalarMul;

pub struct VartimePrecomputedStraus {}

impl VartimePrecomputedMultiscalarMul for VartimePrecomputedStraus {
    type Point = EdwardsPoint;

    fn new<I>(_static_points: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Point>,
    {
        Self {}
    }

    fn optional_mixed_multiscalar_mul<I, J, K>(
        &self,
        _static_scalars: I,
        _dynamic_scalars: J,
        _dynamic_points: K,
    ) -> Option<Self::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator<Item = Option<Self::Point>>,
    {
        unimplemented!()
    }
}