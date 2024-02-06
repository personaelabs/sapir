use super::add::ec_add_complete;
use crate::{
    constraint_system::{ConstraintSystem, Wire},
    frontend::gadgets::AffinePoint,
};
use ark_ff::Field;

// Naive double-and-add algorithm
pub fn ec_mul<F: Field>(
    p: AffinePoint<F>,
    s_bits: &[Wire<F>],
    d: F,
    a: F,
    cs: &mut ConstraintSystem<F>,
) -> AffinePoint<F> {
    let infinity = AffinePoint::new(cs.zero(), cs.one());
    let mut result = infinity;
    let mut current = p;

    for s_i in s_bits {
        let t_x = *s_i * current.x;
        let t_y = *s_i * current.y + (cs.one() - *s_i);
        let t = AffinePoint::new(t_x, t_y);

        result = ec_add_complete(t, result, d, a);
        current = ec_add_complete(current.clone(), current, d, a);
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::test_var_pub_input;

    use super::*;
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed25519::Fr;
    use ark_ed25519::{EdwardsAffine, EdwardsConfig};
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;

    type Fp = ark_ed25519::Fq;

    #[test]
    pub fn test_twisted_ec_mul() {
        let synthesizer = |cs: &mut ConstraintSystem<Fp>| {
            let p_x = cs.alloc_priv_input();
            let p_y = cs.alloc_priv_input();

            let s_bits = cs.alloc_priv_inputs(256);

            let p = AffinePoint::new(p_x, p_y);
            let d = EdwardsConfig::COEFF_D;
            let a = EdwardsConfig::COEFF_A;

            let out = ec_mul(p, &s_bits, d, a, cs);

            cs.expose_public(out.x);
            cs.expose_public(out.y);
        };

        let p = EdwardsAffine::generator();
        let s = Fr::from(3u32);

        let s_bits = s
            .into_bigint()
            .to_bits_le()
            .iter()
            .map(|b| Fp::from(*b))
            .collect::<Vec<Fp>>();

        let out = (p * s).into_affine();
        let pub_input = vec![out.x, out.y];
        let mut priv_input = vec![p.x, p.y];
        priv_input.extend_from_slice(&s_bits);

        test_var_pub_input(synthesizer, &pub_input, &priv_input);
    }
}
