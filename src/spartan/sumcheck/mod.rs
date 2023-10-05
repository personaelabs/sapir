mod sc_phase_1;
mod sc_phase_2;
pub mod sumcheck;
pub mod unipoly;

use super::ipa::InnerProductProof;
use ark_ec::{CurveConfig, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub use sc_phase_1::SumCheckPhase1;
pub use sc_phase_2::SumCheckPhase2;

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumCheckProof<C: CurveGroup> {
    pub label: String,
    pub round_poly_coeffs: Vec<Vec<<C::Config as CurveConfig>::ScalarField>>,
    pub blinder_poly_sum: <C::Config as CurveConfig>::ScalarField,
    pub blinder_poly_eval_proof: InnerProductProof<C>,
}
