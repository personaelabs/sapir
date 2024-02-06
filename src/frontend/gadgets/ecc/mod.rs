use crate::frontend::constraint_system::Wire;
use ark_ff::Field;

pub mod twisted_edwards;
pub mod weierstrass;

#[derive(Copy, Clone)]
pub struct AffinePoint<F: Field> {
    pub x: Wire<F>,
    pub y: Wire<F>,
}

impl<F: Field> AffinePoint<F> {
    pub fn new(x: Wire<F>, y: Wire<F>) -> Self {
        Self { x, y }
    }
}
