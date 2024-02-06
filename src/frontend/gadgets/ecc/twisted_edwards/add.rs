use crate::frontend::gadgets::AffinePoint;
use ark_ff::Field;

// Complete addition for Twisted Edwards curves.
// 6 Arithmetic on Twisted Edwards Curves,  https://eprint.iacr.org/2008/013.pdf
pub fn ec_add_complete<F: Field>(
    p: AffinePoint<F>,
    q: AffinePoint<F>,
    d: F,
    a: F,
) -> AffinePoint<F> {
    let cs = p.x.cs();

    // Compute the x-coordinate
    let x1x2 = p.x * q.x;
    let y1y2 = p.y * q.y;
    let x1x2y1y2 = x1x2 * y1y2;

    let dx1x2y1y2 = cs.mul_const(x1x2y1y2, d);

    let x1y2 = p.x * q.y;
    let y1x2 = p.y * q.x;

    let denominator_x = cs.one() + dx1x2y1y2;
    let numerator_x = x1y2 + y1x2;

    let out_x = numerator_x.div_or_zero(denominator_x);

    // Compute the y-coordinate
    let denominator_y = cs.one() - dx1x2y1y2;
    let numerator_y = y1y2 - cs.mul_const(x1x2, a);
    let out_y = numerator_y.div_or_zero(denominator_y);

    AffinePoint::new(out_x, out_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::constraint_system::ConstraintSystem;
    use crate::test_var_pub_input;
    use ark_ec::twisted_edwards::{MontCurveConfig, TECurveConfig};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed25519::EdwardsAffine;
    use ark_ed25519::EdwardsConfig;
    use ark_ed25519::Fr;

    type Fq = ark_ed25519::Fq;

    fn add_complete_circuit<F: Field>(cs: &mut ConstraintSystem<F>, d: F, a: F) {
        let p_x = cs.alloc_priv_input();
        let p_y = cs.alloc_priv_input();

        let q_x = cs.alloc_priv_input();
        let q_y = cs.alloc_priv_input();

        let p = AffinePoint::new(p_x, p_y);
        let q = AffinePoint::new(q_x, q_y);

        let out: AffinePoint<F> = ec_add_complete(p, q, d, a);

        cs.expose_public(out.x);
        cs.expose_public(out.x);
    }

    #[test]
    pub fn test_twisted_add_complete() {
        let synthesizer = |cs: &mut ConstraintSystem<Fq>| {
            add_complete_circuit(
                cs,
                <EdwardsConfig as TECurveConfig>::COEFF_D,
                <EdwardsConfig as TECurveConfig>::COEFF_A,
            )
        };

        let zero = EdwardsAffine::zero();

        let p_nonzero = (EdwardsAffine::generator() * Fr::from(124221521521u64)).into_affine();
        let q_nonzero = (EdwardsAffine::generator() * Fr::from(11321153521u64)).into_affine();

        let cases = [
            (zero, zero),
            (zero, p_nonzero),
            (p_nonzero, zero),
            (p_nonzero, -q_nonzero),
            (p_nonzero, q_nonzero),
        ];

        let mut cs = ConstraintSystem::<Fq>::new();
        cs.set_constraints(&synthesizer);

        for (p, q) in cases {
            let out = (p + q).into_affine();
            let pub_input = vec![out.x, out.y];
            let priv_input = vec![p.x, p.y, q.x, q.y];

            /*
            let witness = cs.gen_witness(&synthesizer, &pub_input, &priv_input);
            assert!(cs.is_sat(&witness, &pub_input));
             */

            test_var_pub_input(synthesizer, &pub_input, &priv_input);
        }
    }
}
