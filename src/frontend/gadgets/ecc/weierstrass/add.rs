use super::super::AffinePoint;
use crate::frontend::constraint_system::ConstraintSystem;
use ark_ff::Field;

// Incomplete addition for short-Weierstrass curves.
// We follow the specification from the halo2 book;
// https://zcash.github.io/halo2/design/gadgets/sinsemilla.html?highlight=incomplete#incomplete-addition
pub fn ec_add_incomplete<F: Field>(p: AffinePoint<F>, q: AffinePoint<F>) -> AffinePoint<F> {
    let cs = p.x.cs();

    let dx = p.x - q.x;
    let dy = p.y - q.y;

    let lambda = dy.div_or_zero(dx);

    // out_x = (lambda * lambda) - p.x - q.x;
    let out_x = cs.constrain(
        &[(lambda, F::ONE)],
        &[(lambda, F::ONE)],
        &[(p.x, -F::ONE), (q.x, -F::ONE)],
    );
    // out_y = lambda * (p.x - out_x) - p.y;
    let out_y = cs.constrain(
        &[(lambda, F::ONE)],
        &[(p.x, F::ONE), (out_x, -F::ONE)],
        &[(p.y, -F::ONE)],
    );

    AffinePoint::new(out_x, out_y)
}

// Complete addition for short-Weierstrass curves.
// We follow the specification from the halo2 book.
// https://zcash.github.io/halo2/design/gadgets/ecc/addition.html#complete-addition
pub fn ec_add_complete<F: Field>(
    p: AffinePoint<F>,
    q: AffinePoint<F>,
    cs: &mut ConstraintSystem<F>,
) -> AffinePoint<F> {
    let is_x_equal = p.x.is_equal(q.x);

    let p_is_zero = p.x.is_zero();
    let q_is_zero = q.x.is_zero();

    let both_zeros = p_is_zero & q_is_zero;

    let is_sym = is_x_equal & (p.y.is_equal(-q.y));
    let is_out_zero = both_zeros.or(is_sym, cs);

    let zero = cs.zero();

    let inc_add = ec_add_incomplete(p, q);

    let out_x = cs
        .if_then(is_out_zero, zero)
        .elif(p_is_zero, q.x, cs)
        .elif(q_is_zero, p.x, cs)
        .else_then(inc_add.x);

    let out_y = cs
        .if_then(is_out_zero, zero)
        .elif(p_is_zero, q.y, cs)
        .elif(q_is_zero, p.y, cs)
        .else_then(inc_add.y);

    AffinePoint::new(out_x, out_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_satisfiability;
    use crate::test_var_pub_input;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_secp256k1::Affine as Secp256k1Affine;
    use ark_secp256k1::Fr;

    type F = ark_secp256k1::Fq;

    fn add_incomplete_circuit<F: Field>(cs: &mut ConstraintSystem<F>) {
        let p_x = cs.alloc_priv_input();
        let p_y = cs.alloc_priv_input();

        let q_x = cs.alloc_priv_input();
        let q_y = cs.alloc_priv_input();

        let p = AffinePoint::new(p_x, p_y);
        let q = AffinePoint::new(q_x, q_y);

        let out = ec_add_incomplete(p, q);

        cs.expose_public(out.x);
        cs.expose_public(out.y);
    }

    #[test]
    pub fn test_add_incomplete() {
        let synthesizer = |cs: &mut ConstraintSystem<F>| add_incomplete_circuit(cs);

        let p = Secp256k1Affine::generator();
        let q = (Secp256k1Affine::generator() * Fr::from(3)).into_affine();

        let out = (p + q).into_affine();

        let pub_input = vec![out.x, out.y];
        let priv_input = vec![p.x, p.y, q.x, q.y];

        test_satisfiability(synthesizer, &pub_input, &priv_input);
    }

    fn add_complete_circuit<F: Field>(cs: &mut ConstraintSystem<F>) {
        let p_x = cs.alloc_priv_input();
        let p_y = cs.alloc_priv_input();

        let q_x = cs.alloc_priv_input();
        let q_y = cs.alloc_priv_input();

        let p = AffinePoint::new(p_x, p_y);
        let q = AffinePoint::new(q_x, q_y);

        let out = ec_add_complete(p, q, cs);

        cs.expose_public(out.x);
        cs.expose_public(out.y);
    }

    #[test]
    pub fn test_add_complete() {
        let synthesizer = |cs: &mut ConstraintSystem<F>| add_complete_circuit(cs);

        let zero = Secp256k1Affine::identity();

        let p_nonzero = (Secp256k1Affine::generator() * Fr::from(124221521521u64)).into_affine();
        let q_nonzero = (Secp256k1Affine::generator() * Fr::from(11321153521u64)).into_affine();

        let cases = [
            (zero, zero),
            (zero, p_nonzero),
            (p_nonzero, zero),
            (p_nonzero, -q_nonzero),
            (p_nonzero, q_nonzero),
        ];

        for (p, q) in cases {
            let out = (p + q).into_affine();

            let pub_input = [out.x, out.y];
            let priv_input = [p.x, p.y, q.x, q.y];

            test_var_pub_input(synthesizer, &pub_input, &priv_input);
        }
    }
}
