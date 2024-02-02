mod add;
mod mul;

use std::marker::PhantomData;

pub use add::ec_add_complete;
pub use mul::ec_mul;

use crate::frontend::constraint_system::Wire;
use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr};

#[derive(Copy, Clone)]
pub struct TEAffinePoint<C: TECurveConfig, A: AffineRepr<Config = C>> {
    pub x: Wire<C::BaseField>,
    pub y: Wire<C::BaseField>,
    _marker: PhantomData<A>,
}

impl<C: TECurveConfig, A: AffineRepr<Config = C>> TEAffinePoint<C, A> {
    pub fn new(x: Wire<C::BaseField>, y: Wire<C::BaseField>) -> Self {
        Self {
            x,
            y,
            _marker: PhantomData,
        }
    }
}
