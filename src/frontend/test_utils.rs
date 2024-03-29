use crate::frontend::constraint_system::ConstraintSystem;
use ark_ff::Field;

#[allow(unused_must_use)]
pub fn mock_circuit<F: Field>(num_cons: usize) -> impl Fn(&mut ConstraintSystem<F>) {
    let synthesizer = move |cs: &mut ConstraintSystem<F>| {
        let a = cs.alloc_priv_input();
        let b = cs.alloc_priv_input();

        // There is always one constraint for all the additions,
        // so we do num_cons - 1 multiplications to
        // obtain a circuit with num_cons constraints.
        for _ in 0..(num_cons - 1) {
            a * b;
        }

        cs.expose_public(a * b);
    };

    synthesizer
}

#[allow(unused_must_use)]
#[allow(dead_code)]
pub fn synthetic_circuit<F: Field>() -> (impl Fn(&mut ConstraintSystem<F>), Vec<F>, Vec<F>, Vec<F>)
{
    let synthesizer = |cs: &mut ConstraintSystem<F>| {
        let w1 = cs.alloc_priv_input();
        let w2 = cs.alloc_pub_input();

        let w3 = w1 + w2;
        let w4 = w1 * w3;

        let w5 = cs.mul_const(w1, F::from(333u32));

        // Expose a wire as a public input
        cs.expose_public(w4);
        cs.expose_public(w5);
    };

    let w1 = F::from(10u32);
    let w2 = F::from(3u32);
    let w3 = w1 + w2;
    let w4 = w1 * w3;
    let w5 = w1 * F::from(333u32);

    let pub_input = vec![w2, w4, w5];

    let priv_wires_offset = 4;

    let mut witness = vec![w1, w3];
    witness.resize(priv_wires_offset, F::ZERO);

    let priv_input = vec![w1];

    (synthesizer, pub_input, priv_input, witness)
}

// 1. Test that the circuit is satisfiable when thew witness and the public input are valid
// 2. Test that the circuit unsatisfiable when the witness or the public input is invalid.
pub fn test_satisfiability<F: Field>(
    synthesizer: impl Fn(&mut ConstraintSystem<F>),
    pub_inputs: &[F],
    priv_inputs: &[F],
) {
    let mut cs = ConstraintSystem::<F>::new();
    cs.set_constraints(&synthesizer);

    let mut witness = cs.gen_witness(&synthesizer, &pub_inputs, &priv_inputs);

    assert!(cs.is_sat(&witness, &pub_inputs));

    // Should assert when the witness is invalid
    for i in 0..cs.num_vars() {
        witness[i] += F::from(3u32);
        assert_eq!(cs.is_sat(&witness, &pub_inputs), false);
        witness[i] -= F::from(3u32);
    }

    // Should assert when the public inputs are invalid
    let mut pub_inputs = pub_inputs.to_vec();
    for i in 0..pub_inputs.len() {
        pub_inputs[i] += F::from(3u32);
        assert_eq!(cs.is_sat(&witness, &pub_inputs), false);
        pub_inputs[i] -= F::from(3u32);
    }
}

// 1. Test that the circuit is satisfiable when thew witness and the public input are valid
// 2. Test that the circuit unsatisfiable when the public input is invalid.
// We need this separate from `test_satisfiability` because some circuits are satisfiable even when the witness is
// randomly modified.
pub fn test_var_pub_input<F: Field>(
    synthesizer: impl Fn(&mut ConstraintSystem<F>),
    pub_inputs: &[F],
    priv_inputs: &[F],
) {
    let mut cs = ConstraintSystem::<F>::new();
    cs.set_constraints(&synthesizer);

    let witness = cs.gen_witness(&synthesizer, &pub_inputs, &priv_inputs);

    assert!(cs.is_sat(&witness, &pub_inputs));

    // Should assert when the public inputs are invalid
    let mut pub_inputs = pub_inputs.to_vec();
    for i in 0..pub_inputs.len() {
        pub_inputs[i] += F::from(1u32);
        assert_eq!(cs.is_sat(&witness, &pub_inputs), false);
        pub_inputs[i] -= F::from(1u32);
    }
}
