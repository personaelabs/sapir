use crate::frontend::constraint_system::Wire;
use ark_ff::BigInteger;
use ark_ff::PrimeField;

pub fn xor_64<F: PrimeField>(a: [Wire<F>; 64], b: [Wire<F>; 64]) -> [Wire<F>; 64] {
    let cs = a[0].cs();
    assert_eq!(a.len(), b.len());
    let mut out = [cs.one(); 64];
    for i in 0..64 {
        out[i] = bit_xor(a[i], b[i]);
    }

    out
}

// (!a) & b
pub fn not_a_and_b<F: PrimeField>(a: Wire<F>, b: Wire<F>) -> Wire<F> {
    let cs = a.cs();

    let one = cs.one();
    // (a * -1 + 1 * 1) * (b * 1) = c
    cs.constrain(&[(a, -F::ONE), (one, F::ONE)], &[(b, F::ONE)], &[])
}

pub fn not_a_and_b_64<F: PrimeField>(a: [Wire<F>; 64], b: [Wire<F>; 64]) -> [Wire<F>; 64] {
    let cs = a[0].cs();
    assert_eq!(a.len(), b.len());
    let mut out = [cs.one(); 64];
    for i in 0..64 {
        out[i] = not_a_and_b(a[i], b[i]);
    }

    out
}

pub fn rotate_left_64<F: PrimeField>(a: [Wire<F>; 64], n: usize) -> [Wire<F>; 64] {
    let mut out = Vec::with_capacity(64);
    for i in 0..64 {
        out.push(a[((i as usize).wrapping_sub(n)) % 64]);
    }

    out.try_into().unwrap()
}

pub fn bit_xor<F: PrimeField>(a: Wire<F>, b: Wire<F>) -> Wire<F> {
    let cs = a.cs();

    // -2a * b + a + b = c
    cs.constrain(
        &[(a, -F::from(2u32))],
        &[(b, F::ONE)],
        &[(a, F::ONE), (b, F::ONE)],
    )
}

// Little-endian bits to byte
pub fn le_bits_to_byte<F: PrimeField>(bits: &[Wire<F>]) -> Wire<F> {
    let cs = bits[0].cs();
    let mut terms = Vec::with_capacity(8);

    let mut pow = F::from(1u32);
    for bit in bits.iter() {
        terms.push((cs.mul_const(*bit, pow), true));
        pow *= F::from(2u32);
    }

    cs.sum(&terms)
}

// Byte to little-endian bits
pub fn byte_to_le_bits<F: PrimeField>(byte: Wire<F>) -> Vec<Wire<F>> {
    let cs = byte.cs();

    let bits = (0..8).map(|_| cs.alloc_var(F::ZERO)).collect::<Vec<_>>();

    if cs.is_witness_gen() {
        let a_assigned = cs.wires[byte.index];
        let mut a_bits = a_assigned.into_bigint().to_bits_le()[..8].to_vec();
        println!("a_bits: {:?}", a_bits);
        a_bits.resize(8, false);

        for (i, b) in a_bits.iter().enumerate() {
            cs.wires[bits[i].index] = F::from(*b);
        }
    }

    let recovered_byte = le_bits_to_byte(&bits);
    println!("byte: ");
    byte.println();
    println!("recovered_byte: ");
    recovered_byte.println();
    cs.assert_equal(byte, recovered_byte, "");

    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::constraint_system::ConstraintSystem;
    use ark_ff::{Field, PrimeField};

    type Fp = ark_secq256k1::Fr;

    #[test]
    pub fn test_le_bits_to_byte() {
        let synthesizer = |cs: &mut ConstraintSystem<Fp>| {
            let bits = cs.alloc_priv_inputs(8);
            let out = le_bits_to_byte(&bits);

            cs.expose_public(out);
        };

        let mut bits = vec![Fp::ZERO; 8];
        bits[2] = Fp::ONE;
        let expected = Fp::from(4);

        let priv_input = bits;
        let pub_input = vec![expected];

        let mut cs = ConstraintSystem::new();
        let witness = cs.gen_witness(synthesizer, &pub_input, &priv_input);

        cs.set_constraints(&synthesizer);
        assert!(cs.is_sat(&witness, &pub_input));
    }

    #[test]
    fn test_byte_to_le_bits() {
        let synthesizer = |cs: &mut ConstraintSystem<Fp>| {
            let val = cs.alloc_priv_input();
            let out = byte_to_le_bits(val);

            for out_i in out {
                cs.expose_public(out_i);
            }
        };

        let val = Fp::from(123);
        let mut expected_bits = val
            .into_bigint()
            .to_bits_le()
            .iter()
            .map(|b| Fp::from(*b))
            .collect::<Vec<Fp>>();
        expected_bits.resize(8, Fp::ZERO);

        let priv_input = [val];
        let pub_input = expected_bits;

        let mut cs = ConstraintSystem::new();
        let witness = cs.gen_witness(synthesizer, &pub_input, &priv_input);

        cs.set_constraints(&synthesizer);
        assert!(cs.is_sat(&witness, &pub_input));
    }
}
