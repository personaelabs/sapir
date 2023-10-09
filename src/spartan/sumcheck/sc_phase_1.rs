use super::sumcheck::{prove_sum, BlinderPoly};
use crate::spartan::hyrax::Hyrax;
use crate::spartan::ipa::IPAComm;
use crate::spartan::polynomial::eq_poly::EqPoly;
use crate::spartan::sumcheck::SumCheckProof;
use crate::spartan::transcript::Transcript;
use crate::ScalarField;
use ark_ec::CurveGroup;

pub struct SumCheckPhase1<C: CurveGroup> {
    Az_evals: Vec<ScalarField<C>>,
    Bz_evals: Vec<ScalarField<C>>,
    Cz_evals: Vec<ScalarField<C>>,
}

impl<C: CurveGroup> SumCheckPhase1<C> {
    pub fn new(
        Az_evals: Vec<ScalarField<C>>,
        Bz_evals: Vec<ScalarField<C>>,
        Cz_evals: Vec<ScalarField<C>>,
    ) -> Self {
        Self {
            Az_evals,
            Bz_evals,
            Cz_evals,
        }
    }

    pub fn prove(
        &self,
        pcs: &Hyrax<C>,
        tau: Vec<ScalarField<C>>,
        blinder_poly_sum: ScalarField<C>,
        blinder_poly: BlinderPoly<ScalarField<C>>,
        blinder_poly_comm: &IPAComm<C>,
        transcript: &mut Transcript<C>,
    ) -> (
        SumCheckProof<C>,
        (ScalarField<C>, ScalarField<C>, ScalarField<C>),
        Vec<ScalarField<C>>,
    ) {
        let poly_num_vars = (self.Az_evals.len() as f64).log2() as usize;
        let poly_degree = 3;

        let mut eval_tables = vec![
            self.Az_evals.clone(),
            self.Bz_evals.clone(),
            self.Cz_evals.clone(),
            EqPoly::new(tau).evals(),
        ];
        let comb_func = |x: &[ScalarField<C>]| (x[0] * x[1] - x[2]) * x[3];

        let (sumcheck_proof, challenge) = prove_sum(
            poly_num_vars,
            poly_degree,
            &mut eval_tables,
            comb_func,
            pcs,
            blinder_poly_sum,
            blinder_poly,
            blinder_poly_comm,
            transcript,
            b"sc_phase_1",
        );

        let v_A = eval_tables[0][0];
        let v_B = eval_tables[1][0];
        let v_C = eval_tables[2][0];

        (sumcheck_proof, (v_A, v_B, v_C), challenge)
    }
}
