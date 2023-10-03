use ark_ec::CurveGroup;
use ark_ff::Field;

use crate::r1cs::Matrix;
use crate::spartan::hyrax::Hyrax;
use crate::spartan::polynomial::eq_poly::EqPoly;
use crate::spartan::sumcheck::SumCheckProof;
use crate::spartan::transcript::Transcript;
use crate::ScalarField;

use super::sumcheck::prove_sum;

pub struct SumCheckPhase2<C: CurveGroup> {
    A_mat: Matrix<ScalarField<C>>,
    B_mat: Matrix<ScalarField<C>>,
    C_mat: Matrix<ScalarField<C>>,
    Z_evals: Vec<ScalarField<C>>,
    rx: Vec<ScalarField<C>>,
    r: [ScalarField<C>; 3],
}

impl<C: CurveGroup> SumCheckPhase2<C> {
    pub fn new(
        A_mat: Matrix<ScalarField<C>>,
        B_mat: Matrix<ScalarField<C>>,
        C_mat: Matrix<ScalarField<C>>,
        Z_evals: Vec<ScalarField<C>>,
        rx: Vec<ScalarField<C>>,
        r: [ScalarField<C>; 3],
    ) -> Self {
        Self {
            A_mat,
            B_mat,
            C_mat,
            Z_evals,
            rx,
            r,
        }
    }

    pub fn prove(&self, pcs: &Hyrax<C>, transcript: &mut Transcript<C>) -> SumCheckProof<C> {
        let r_A = self.r[0];
        let r_B = self.r[1];
        let r_C = self.r[2];

        let n = self.Z_evals.len();
        let num_vars = (self.Z_evals.len() as f64).log2() as usize;

        let evals_rx = EqPoly::new(self.rx.clone()).evals();
        let mut A_evals = vec![ScalarField::<C>::ZERO; n];
        let mut B_evals = vec![ScalarField::<C>::ZERO; n];
        let mut C_evals = vec![ScalarField::<C>::ZERO; n];

        for entry in &self.A_mat.entries {
            A_evals[entry.col] += evals_rx[entry.row] * entry.val;
        }
        for entry in &self.B_mat.entries {
            B_evals[entry.col] += evals_rx[entry.row] * entry.val;
        }
        for entry in &self.C_mat.entries {
            C_evals[entry.col] += evals_rx[entry.row] * entry.val;
        }

        let mut eval_tables = vec![
            A_evals.clone(),
            B_evals.clone(),
            C_evals.clone(),
            self.Z_evals.clone(),
        ];

        let poly_degree = 2;
        let comb_func = |x: &[ScalarField<C>]| (x[0] * r_A + x[1] * r_B + x[2] * r_C) * x[3];

        prove_sum(
            num_vars,
            poly_degree,
            &mut eval_tables,
            comb_func,
            pcs,
            transcript,
            "sc_phase_2".to_string(),
        )
    }
}
