mod sc_phase_1;
mod sc_phase_2;
pub mod sumcheck;
pub mod unipoly;

use super::ipa::InnerProductProof;
use crate::ScalarField;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub use sc_phase_1::SumCheckPhase1;
pub use sc_phase_2::SumCheckPhase2;

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumCheckProof<C: CurveGroup> {
    pub round_poly_coeffs: Vec<Vec<ScalarField<C>>>,
    pub blinder_poly_sum: ScalarField<C>,
    pub blinder_poly_eval_proof: InnerProductProof<C>,
}
