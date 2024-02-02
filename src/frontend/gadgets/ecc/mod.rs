use crate::frontend::constraint_system::Wire;
use ark_ec::AffineRepr;

pub mod twisted_edwards;
pub mod weierstrass;

#[derive(Copy, Clone)]
pub struct AffinePoint<C: AffineRepr> {
    pub x: Wire<C::BaseField>,
    pub y: Wire<C::BaseField>,
}

impl<C: AffineRepr> AffinePoint<C> {
    pub fn new(x: Wire<C::BaseField>, y: Wire<C::BaseField>) -> Self {
        Self { x, y }
    }
}
