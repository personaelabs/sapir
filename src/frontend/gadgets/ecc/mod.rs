use crate::frontend::constraint_system::Wire;
use ark_ff::PrimeField;

pub mod add;
pub mod double;
pub mod mul;

#[derive(Copy, Clone)]
pub struct AffinePoint<F: PrimeField> {
    pub x: Wire<F>,
    pub y: Wire<F>,
}

impl<F: PrimeField> AffinePoint<F> {
    pub fn new(x: Wire<F>, y: Wire<F>) -> Self {
        Self { x, y }
    }
}
