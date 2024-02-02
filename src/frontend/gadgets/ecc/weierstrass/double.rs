use super::super::AffinePoint;
use crate::frontend::constraint_system::ConstraintSystem;
use ark_ec::AffineRepr;

// Doubling for short-Weierstrass curves
pub fn ec_double<C: AffineRepr>(
    p: AffinePoint<C>,
    cs: &mut ConstraintSystem<C::BaseField>,
) -> AffinePoint<C> {
    // lambda = (3 * x^2) / (2 * y)
    let lambda = (cs.alloc_const(C::BaseField::from(3u32)) * (p.x * p.x))
        / (cs.alloc_const(C::BaseField::from(2u32)) * p.y);

    // x = lambda^2 - 2 * x
    let out_x = (lambda * lambda) - (p.x * cs.alloc_const(C::BaseField::from(2u32)));
    // y = lambda * (x - out_x) - y
    let out_y = lambda * (p.x - out_x) - p.y;

    AffinePoint::new(out_x, out_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_satisfiability;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_secp256k1::Affine as Secp256k1Affine;
    use ark_secp256k1::Fr;

    type F = ark_secq256k1::Fr;

    #[test]
    fn test_ec_double() {
        let synthesizer = |cs: &mut ConstraintSystem<F>| {
            let p_x = cs.alloc_priv_input();
            let p_y = cs.alloc_priv_input();

            let p = AffinePoint::<Secp256k1Affine>::new(p_x, p_y);

            let out = ec_double(p, cs);

            cs.expose_public(out.x);
            cs.expose_public(out.y);
        };

        let p = (Secp256k1Affine::generator() * Fr::from(3)).into_affine();
        let p_double = (p + p).into_affine();

        let pub_input = [p_double.x, p_double.y];
        let priv_input = [p.x, p.y];

        test_satisfiability(synthesizer, &pub_input, &priv_input);
    }
}