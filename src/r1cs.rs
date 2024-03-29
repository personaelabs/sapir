use crate::spartan::polynomial::sparse_ml_poly::SparseMLPoly;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SparseMatrixEntry<F: Field> {
    pub row: usize,
    pub col: usize,
    pub val: F,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Matrix<F: Field> {
    pub entries: Vec<SparseMatrixEntry<F>>,
    pub num_cols: usize,
    pub num_rows: usize,
}

impl<F: Field> Matrix<F> {
    pub const fn empty() -> Self {
        Self {
            entries: vec![],
            num_cols: 0,
            num_rows: 0,
        }
    }

    pub fn new(entries: Vec<SparseMatrixEntry<F>>, num_cols: usize, num_rows: usize) -> Self {
        Self {
            entries,
            num_cols,
            num_rows,
        }
    }

    pub fn mul_vector(&self, vec: &[F]) -> Vec<F> {
        debug_assert_eq!(vec.len(), self.num_cols);
        let mut result = vec![F::ZERO; self.num_rows];
        let entries = &self.entries;
        for i in 0..entries.len() {
            let row = entries[i].row;
            let col = entries[i].col;
            let val = entries[i].val;
            result[row] += val * vec[col];
        }
        result
    }

    // Return a multilinear extension of the matrix
    // with log2(num_cols) * 2 variables
    pub fn to_ml_extension(&self) -> SparseMLPoly<F> {
        let mut evals = Vec::with_capacity(self.entries.len());
        let entries = &self.entries;
        let num_cols = self.num_cols as u64;
        for i in 0..entries.len() {
            let row = entries[i].row as u64;
            let col = entries[i].col as u64;
            let val = entries[i].val;
            evals.push(((row * num_cols) + col, val));
        }

        let num_vars = ((self.num_cols as f64).log2() as usize) * 2;

        let ml_poly = SparseMLPoly::new(evals, num_vars);
        ml_poly
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CS<F: Field> {
    pub A: Matrix<F>,
    pub B: Matrix<F>,
    pub C: Matrix<F>,
    pub num_vars: usize,
    pub num_input: usize,
}

impl<F: Field> R1CS<F> {
    pub const fn empty() -> Self {
        Self {
            A: Matrix::empty(),
            B: Matrix::empty(),
            C: Matrix::empty(),
            num_vars: 0,
            num_input: 0,
        }
    }

    pub fn hadamard_prod(a: &[F], b: &[F]) -> Vec<F> {
        assert_eq!(a.len(), b.len());
        let mut result = vec![F::ZERO; a.len()];
        for i in 0..a.len() {
            result[i] = a[i] * b[i];
        }
        result
    }

    pub fn num_cons(&self) -> usize {
        self.A.entries.len()
    }

    pub fn z_len(&self) -> usize {
        self.num_vars.next_power_of_two() * 2
    }

    pub fn construct_z(witness: &[F], public_input: &[F]) -> Vec<F> {
        assert!(witness.len() >= public_input.len());
        // Z = (1, io, witness)
        let n = witness.len().next_power_of_two();
        let mut z = vec![];
        z.push(F::ONE);
        z.extend_from_slice(public_input);
        z.resize(n, F::ZERO);

        z.extend_from_slice(witness);
        z.resize(n * 2, F::ZERO);

        z
    }

    pub fn produce_synthetic_r1cs(num_vars: usize, num_input: usize) -> (Self, Vec<F>, Vec<F>) {
        let mut public_input = Vec::with_capacity(num_input);
        let mut witness = Vec::with_capacity(num_vars);

        for i in 0..num_input {
            public_input.push(F::from((i + 1) as u64));
        }

        for i in 0..num_vars {
            witness.push(F::from((i + 1) as u64));
        }

        let z = Self::construct_z(&witness, &public_input);

        let mut A_entries: Vec<SparseMatrixEntry<F>> = vec![];
        let mut B_entries: Vec<SparseMatrixEntry<F>> = vec![];
        let mut C_entries: Vec<SparseMatrixEntry<F>> = vec![];

        // Constrain the variables
        let witness_start_index = num_vars.next_power_of_two();
        for i in witness_start_index..(witness_start_index + num_vars) {
            let A_col = i;
            let B_col = (i + 1) % (witness_start_index + num_vars);
            let C_col = (i + 2) % (witness_start_index + num_vars);

            // For the i'th constraint,
            // add the value 1 at the (i % num_vars)th column of A, B.
            // Compute the corresponding C_column value so that A_i * B_i = C_i
            // we apply multiplication since the Hadamard product is computed for Az ・ Bz,

            // We only _enable_ a single variable in each constraint.
            let AB = if z[C_col] == F::ZERO { F::ZERO } else { F::ONE };

            A_entries.push(SparseMatrixEntry {
                row: i,
                col: A_col,
                val: AB,
            });
            B_entries.push(SparseMatrixEntry {
                row: i,
                col: B_col,
                val: AB,
            });
            C_entries.push(SparseMatrixEntry {
                row: i,
                col: C_col,
                val: if z[C_col] == F::ZERO {
                    F::ZERO
                } else {
                    (z[A_col] * z[B_col]) * z[C_col].inverse().unwrap()
                },
            });
        }

        // Constrain the public inputs
        let input_index_start = 1;
        for i in input_index_start..(input_index_start + num_input) {
            let A_col = i;
            let B_col = (i + 1) % input_index_start + num_input;
            let C_col = (i + 2) % input_index_start + num_input;

            // For the i'th constraint,
            // add the value 1 at the (i % num_vars)th column of A, B.
            // Compute the corresponding C_column value so that A_i * B_i = C_i
            // we apply multiplication since the Hadamard product is computed for Az ・ Bz,

            // We only _enable_ a single variable in each constraint.
            let AB = if z[C_col] == F::ZERO { F::ZERO } else { F::ONE };

            A_entries.push(SparseMatrixEntry {
                row: i,
                col: A_col,
                val: AB,
            });
            B_entries.push(SparseMatrixEntry {
                row: i,
                col: B_col,
                val: AB,
            });
            C_entries.push(SparseMatrixEntry {
                row: i,
                col: C_col,
                val: if z[C_col] == F::ZERO {
                    F::ZERO
                } else {
                    (z[A_col] * z[B_col]) * z[C_col].inverse().unwrap()
                },
            });
        }

        let num_cols = z.len();
        let num_rows = z.len();

        let A = Matrix::new(A_entries, num_cols, num_rows);
        let B = Matrix::new(B_entries, num_cols, num_rows);
        let C = Matrix::new(C_entries, num_cols, num_rows);

        (
            Self {
                A,
                B,
                C,
                num_vars,
                num_input,
            },
            witness,
            public_input,
        )
    }

    pub fn is_sat(&self, witness: &[F], public_input: &[F]) -> bool {
        let z = Self::construct_z(witness, public_input);
        let Az = self.A.mul_vector(&z);
        let Bz = self.B.mul_vector(&z);
        let Cz = self.C.mul_vector(&z);

        Self::hadamard_prod(&Az, &Bz) == Cz
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    type F = ark_secq256k1::Fr;

    use crate::spartan::polynomial::ml_poly::MlPoly;

    // Returns a vector of vectors of length m, where each vector is a boolean vector (big endian)
    fn boolean_hypercube<F: Field>(m: usize) -> Vec<Vec<F>> {
        let n = 2usize.pow(m as u32);

        let mut boolean_hypercube = Vec::<Vec<F>>::with_capacity(n);

        for i in 0..n {
            let mut tmp = Vec::with_capacity(m);
            for j in 0..m {
                let i_b = F::from((i >> j & 1) as u64);
                tmp.push(i_b);
            }
            tmp.reverse();
            boolean_hypercube.push(tmp);
        }

        boolean_hypercube
    }

    #[test]
    fn test_r1cs() {
        let ZERO = F::from(0u32);
        let ONE = F::from(1u32);

        let num_cons = 10;
        let num_input = 3;
        let num_vars = num_cons - num_input;

        let (r1cs, mut witness, pub_input) = R1CS::<F>::produce_synthetic_r1cs(num_vars, num_input);
        assert_eq!(r1cs.num_cons(), num_cons);

        assert_eq!(witness.len(), num_vars);
        assert_eq!(pub_input.len(), num_input);

        assert!(r1cs.is_sat(&witness, &pub_input));

        // Should assert if the witness is invalid
        witness[0] = witness[0] + ONE;
        assert!(r1cs.is_sat(&witness, &pub_input) == false);
        witness[0] = witness[0] - ONE;

        // Should assert if the public input is invalid
        let mut public_input = pub_input.clone();
        public_input[0] = public_input[0] + ONE;
        assert!(r1cs.is_sat(&witness, &public_input) == false);
        public_input[0] = public_input[0] - ONE;

        // Test MLE
        let A_mle = r1cs.A.to_ml_extension();
        let B_mle = r1cs.B.to_ml_extension();
        let C_mle = r1cs.C.to_ml_extension();
        let z = R1CS::construct_z(&witness, &public_input);
        let Z_mle = MlPoly::new(z);

        let s = Z_mle.num_vars;
        for c in &boolean_hypercube(s) {
            let mut eval_a = ZERO;
            let mut eval_b = ZERO;
            let mut eval_c = ZERO;
            for b in &boolean_hypercube(s) {
                let z_eval = Z_mle.eval(&b);
                let eval_matrix = [c.as_slice(), b.as_slice()].concat();
                eval_a += A_mle.eval(&eval_matrix) * z_eval;
                eval_b += B_mle.eval(&eval_matrix) * z_eval;
                eval_c += C_mle.eval(&eval_matrix) * z_eval;
            }
            let eval_con = eval_a * eval_b - eval_c;
            assert_eq!(eval_con, ZERO);
        }
    }

    #[test]
    fn test_construct_z() {
        let ZERO = F::from(0u32);
        let ONE = F::from(1u32);

        let num_cons = 10;
        let num_input = 3;
        let num_vars = num_cons - num_input;

        let (_, witness, pub_input) = R1CS::<F>::produce_synthetic_r1cs(num_vars, num_input);

        let Z = R1CS::construct_z(&witness, &pub_input);
        // Test that the followings hold
        // - Z(0, x1, x2, ... ,xm) = MLE(1, IO(x1, x2, ..., xm))
        // - Z(1, x1, x2, ... ,xm) = W(x1, x2, ... ,xm)

        let Z_mle = MlPoly::new(Z.clone());

        assert_eq!(
            Z_mle.num_vars,
            (num_vars.next_power_of_two() as f64).log2() as usize + 1
        );

        // Check the evaluation when x0 = 1 (the evaluations should be the public input)
        for (i, b) in boolean_hypercube(Z_mle.num_vars - 1).iter().enumerate() {
            if i == 0 {
                // The first entry in the Lagrange basis polynomial should equal one
                assert_eq!(ONE, Z_mle.eval(&[&[ZERO], b.as_slice()].concat()));
            } else if (i - 1) < pub_input.len() {
                assert_eq!(
                    pub_input[i - 1],
                    Z_mle.eval(&[&[ZERO], b.as_slice()].concat())
                );
            } else {
                // The "extended" entries should be all zeros.
                assert_eq!(ZERO, Z_mle.eval(&[&[ZERO], b.as_slice()].concat()));
            }
        }

        for (i, b) in boolean_hypercube(Z_mle.num_vars - 1).iter().enumerate() {
            if i < witness.len() {
                assert_eq!(witness[i], Z_mle.eval(&[&[ONE], b.as_slice()].concat()));
            } else {
                // The "extended" entries should be all zeros.
                assert_eq!(ZERO, Z_mle.eval(&[&[ONE], b.as_slice()].concat()));
            }
        }
    }

    #[test]
    fn test_z_len() {
        let num_cons = 10;
        let num_input = 3;
        let num_vars = num_cons - num_input;

        let (r1cs, witness, pub_input) = R1CS::<F>::produce_synthetic_r1cs(num_vars, num_input);

        let z = R1CS::construct_z(&witness, &pub_input);
        assert_eq!(z.len(), r1cs.z_len());
    }
}
