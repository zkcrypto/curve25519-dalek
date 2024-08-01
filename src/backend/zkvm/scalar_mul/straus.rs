use core::borrow::Borrow;
use edwards::EdwardsPoint;
use scalar::Scalar;
use traits::{MultiscalarMul, VartimeMultiscalarMul};

pub struct Straus {}

impl MultiscalarMul for Straus {
    type Point = EdwardsPoint;

    fn multiscalar_mul<I, J>(_scalars: I, _points: J) -> EdwardsPoint
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<EdwardsPoint>,
    {
        unimplemented!("Straus is not supported yet for zkvm")
    }
}

impl VartimeMultiscalarMul for Straus {
    type Point = EdwardsPoint;

    fn optional_multiscalar_mul<I, J>(_scalars: I, _points: J) -> Option<EdwardsPoint>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<EdwardsPoint>>,
    {
        unimplemented!("Straus is not supported yet for zkvm")
    }
}