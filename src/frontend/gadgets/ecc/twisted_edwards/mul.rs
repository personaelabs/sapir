use super::add::ec_add_complete;
use super::TEAffinePoint;
use crate::constraint_system::{ConstraintSystem, Wire};
use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr};

// Naive double-and-add algorithm
pub fn ec_mul<C: TECurveConfig + Clone, A: AffineRepr<Config = C>>(
    p: TEAffinePoint<C, A>,
    s_bits: &[Wire<C::BaseField>],
    cs: &mut ConstraintSystem<C::BaseField>,
) -> TEAffinePoint<C, A> {
    let infinity = TEAffinePoint::new(cs.zero(), cs.one());
    let mut result = infinity;
    let mut current = p;

    for s_i in s_bits {
        let t_x = *s_i * current.x;
        let t_y = *s_i * current.y + (cs.one() - *s_i);
        let t = TEAffinePoint::new(t_x, t_y);

        result = ec_add_complete::<C, A>(t, result);
        current = ec_add_complete::<C, A>(current.clone(), current);
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::test_var_pub_input;

    use super::*;
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

            let p = TEAffinePoint::<EdwardsConfig, EdwardsAffine>::new(p_x, p_y);

            let out = ec_mul(p, &s_bits, cs);

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
