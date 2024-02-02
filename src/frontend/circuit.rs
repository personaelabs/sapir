use ark_ff::Field;

use crate::{constraint_system::ConstraintSystem, wasm::prelude::R1CS};

pub struct Circuit<F: Field> {
    cs: ConstraintSystem<F>,
    synthesizer: fn(&mut ConstraintSystem<F>),
}

impl<F: Field> Circuit<F> {
    pub fn new(synthesizer: fn(&mut ConstraintSystem<F>)) -> Self {
        let mut cs = ConstraintSystem::new();
        cs.set_constraints(&synthesizer);
        Self { synthesizer, cs }
    }

    pub fn gen_witness(&mut self, pub_inputs: &[F], priv_inputs: &[F]) -> Vec<F> {
        self.cs
            .gen_witness(self.synthesizer, pub_inputs, priv_inputs)
    }

    pub fn is_sat(&self, witness: &[F], pub_inputs: &[F]) -> bool {
        self.cs.is_sat(witness, pub_inputs)
    }

    pub fn to_r1cs(&self) -> R1CS<F> {
        self.cs.to_r1cs()
    }
}
