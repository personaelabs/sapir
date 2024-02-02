use crate::frontend::constraint_system::{ConstraintSystem, Wire};
use ark_ff::Field;
use poseidon::PoseidonConstants;

#[derive(Clone)]
pub struct PoseidonChip<F: Field, const WIDTH: usize> {
    pub state: [Wire<F>; WIDTH],
    pub pos: usize,
    constants: PoseidonConstants<F>,
    cs: *mut ConstraintSystem<F>,
}

impl<F: Field, const WIDTH: usize> PoseidonChip<F, WIDTH> {
    pub fn new(cs_ptr: *mut ConstraintSystem<F>, constants: PoseidonConstants<F>) -> Self {
        let cs = unsafe { &mut *cs_ptr };
        let zero = cs.zero();
        let init_state = [zero; WIDTH];

        Self {
            state: init_state,
            constants,
            pos: 0,
            cs: cs_ptr,
        }
    }

    fn cs(&self) -> &mut ConstraintSystem<F> {
        unsafe { &mut *self.cs as &mut ConstraintSystem<F> }
    }

    pub fn reset(&mut self) {
        let cs = self.cs();
        let zero = cs.zero();
        self.state = [zero; WIDTH];
        self.pos = 0;
    }

    // MDS matrix multiplication
    fn matrix_mul(&mut self) {
        let mut result = [self.cs().one(); WIDTH];

        for (i, matrix) in self.constants.mds_matrix.iter().enumerate() {
            let deg2_comb_a = [
                (self.state[0], matrix[0]),
                (self.state[1], matrix[1]),
                (self.state[2], matrix[2]),
            ];

            let deg2_comb_b = [(self.cs().one(), F::ONE)];
            let deg_2_comb_c = [];
            result[i] = self
                .cs()
                .constrain(&deg2_comb_a, &deg2_comb_b, &deg_2_comb_c);
        }

        self.state = result;
    }

    fn full_round(&mut self) {
        let t = self.state.len();

        // Add round constants and apply the S-boxes
        for i in 0..t {
            let square = self.cs().constrain(
                &[
                    (self.state[i], F::ONE),
                    (self.cs().one(), self.constants.round_keys[self.pos + i]),
                ],
                &[
                    (self.state[i], F::ONE),
                    (self.cs().one(), self.constants.round_keys[self.pos + i]),
                ],
                &[],
            );
            let quadruple = square * square;

            self.state[i] = self.cs().constrain(
                &[(quadruple, F::ONE)],
                &[
                    (self.state[i], F::ONE),
                    (self.cs().one(), self.constants.round_keys[self.pos + i]),
                ],
                &[],
            );
        }

        self.matrix_mul();

        // Update the position of the round constants that are added
        self.pos += self.state.len();
    }

    fn partial_round(&mut self) {
        // Apply the round constants
        for i in 1..3 {
            self.state[i] = self
                .cs()
                .add_const(self.state[i], self.constants.round_keys[self.pos + i]);
        }

        // S-box

        let square = self.cs().constrain(
            &[
                (self.state[0], F::ONE),
                (self.cs().one(), self.constants.round_keys[self.pos + 0]),
            ],
            &[
                (self.state[0], F::ONE),
                (self.cs().one(), self.constants.round_keys[self.pos + 0]),
            ],
            &[],
        );
        let quadruple = square * square;

        self.state[0] = self.cs().constrain(
            &[(quadruple, F::ONE)],
            &[
                (self.state[0], F::ONE),
                (self.cs().one(), self.constants.round_keys[self.pos + 0]),
            ],
            &[],
        );

        self.matrix_mul();

        // Update the position of the round constants that are added
        self.pos += self.state.len();
    }

    pub fn permute(&mut self) {
        // ########################
        // First half of the full rounds
        // ########################

        // First half of full rounds
        for _ in 0..self.constants.num_full_rounds / 2 {
            self.full_round();
        }

        // Partial rounds
        for _ in 0..self.constants.num_partial_rounds {
            self.partial_round();
        }

        // Second half of full rounds
        for _ in 0..self.constants.num_full_rounds / 2 {
            self.full_round();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::test_utils::test_satisfiability;
    use poseidon::{constants::secp256k1_w3, Poseidon};

    type F = ark_secq256k1::Fr;

    #[test]
    fn test_poseidon() {
        const WIDTH: usize = 3;
        let tag = F::from(3);

        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();

            let mut poseidon_chip = PoseidonChip::<_, WIDTH>::new(cs, secp256k1_w3());
            poseidon_chip.state[0] = a;
            poseidon_chip.state[1] = a;
            poseidon_chip.state[2] = b;

            poseidon_chip.permute();

            let out = poseidon_chip.state[1];
            cs.expose_public(out);
        };

        let mut poseidon = Poseidon::<F, WIDTH>::new(secp256k1_w3());

        let a = F::from(3);
        let b = F::from(4);

        poseidon.state[0] = tag;
        poseidon.state[1] = a;
        poseidon.state[2] = b;

        poseidon.permute();

        let expected_out = poseidon.state[1];

        let priv_input = [a, b];
        let pub_input = [expected_out];

        test_satisfiability(synthesizer, &pub_input, &priv_input);
    }
}
