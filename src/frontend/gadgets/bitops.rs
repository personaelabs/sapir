use crate::frontend::constraint_system::Wire;
use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::PrimeField;

pub fn xor_64<F: Field>(a: [Wire<F>; 64], b: [Wire<F>; 64]) -> [Wire<F>; 64] {
    let cs = a[0].cs();
    assert_eq!(a.len(), b.len());
    let mut out = [cs.one(); 64];
    for i in 0..64 {
        out[i] = bit_xor(a[i], b[i]);
    }

    out
}

// (!a) & b
pub fn not_a_and_b<F: Field>(a: Wire<F>, b: Wire<F>) -> Wire<F> {
    let cs = a.cs();

    let one = cs.one();
    // (a * -1 + 1 * 1) * (b * 1) = c
    cs.constrain(&[(a, -F::ONE), (one, F::ONE)], &[(b, F::ONE)], &[])
}

pub fn not_a_and_b_64<F: Field>(a: [Wire<F>; 64], b: [Wire<F>; 64]) -> [Wire<F>; 64] {
    let cs = a[0].cs();
    assert_eq!(a.len(), b.len());
    let mut out = [cs.one(); 64];
    for i in 0..64 {
        out[i] = not_a_and_b(a[i], b[i]);
    }

    out
}

pub fn rotate_left_64<F: Field>(a: [Wire<F>; 64], n: usize) -> [Wire<F>; 64] {
    let mut out = Vec::with_capacity(64);
    for i in 0..64 {
        out.push(a[((i as usize).wrapping_sub(n)) % 64]);
    }

    out.try_into().unwrap()
}

pub fn bit_xor<F: Field>(a: Wire<F>, b: Wire<F>) -> Wire<F> {
    let cs = a.cs();

    // -2a * b + a + b = c
    cs.constrain(
        &[(a, -F::from(2u32))],
        &[(b, F::ONE)],
        &[(a, F::ONE), (b, F::ONE)],
    )
}

// Little-endian bits to value
pub fn form_le_bits<F: PrimeField>(bits: &[Wire<F>]) -> Wire<F> {
    let cs = bits[0].cs();

    let mut terms = Vec::with_capacity(bits.len());

    let mut pow = F::from(1u32);
    for bit in bits.iter() {
        terms.push((cs.mul_const(*bit, pow), true));
        pow *= F::from(2u32);
    }

    cs.sum(&terms)
}

// Value to little-endian bits
pub fn to_le_bits<F: PrimeField>(x: Wire<F>) -> Vec<Wire<F>> {
    let cs = x.cs();

    let bits = (0..F::MODULUS_BIT_SIZE)
        .map(|_| cs.alloc_var(F::ZERO))
        .collect::<Vec<_>>();

    if cs.is_witness_gen() {
        let x_assigned = cs.wires[x.index];
        let x_bits = x_assigned.into_bigint().to_bits_le();

        for (i, b) in x_bits.iter().enumerate() {
            cs.wires[bits[i].index] = F::from(*b);
        }
    }

    let recovered_x = form_le_bits(&bits);
    cs.assert_equal(x, recovered_x, "to_le_bits failed");

    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frontend::constraint_system::ConstraintSystem, test_var_pub_input};
    use ark_ff::Field;

    type Fp = ark_secq256k1::Fr;

    #[test]
    pub fn test_from_le_bits() {
        let synthesizer = |cs: &mut ConstraintSystem<Fp>| {
            let bits = cs.alloc_priv_inputs(Fp::MODULUS_BIT_SIZE as usize);
            let out = form_le_bits(&bits);

            cs.expose_public(out);
        };

        let mut bits = vec![Fp::ZERO; Fp::MODULUS_BIT_SIZE as usize];
        bits[2] = Fp::ONE;
        let expected = Fp::from(4);

        let priv_input = bits;
        let pub_input = vec![expected];

        test_var_pub_input(synthesizer, &pub_input, &priv_input);
    }

    #[test]
    fn test_to_le_bits() {
        let synthesizer = |cs: &mut ConstraintSystem<Fp>| {
            let val = cs.alloc_priv_input();
            let out = to_le_bits(val);

            for out_i in out {
                cs.expose_public(out_i);
            }
        };

        let val = Fp::from(123);
        let expected_bits = val
            .into_bigint()
            .to_bits_le()
            .iter()
            .map(|b| Fp::from(*b))
            .collect::<Vec<Fp>>();

        let priv_input = [val];
        let pub_input = expected_bits;

        test_var_pub_input(synthesizer, &pub_input, &priv_input);
    }
}
