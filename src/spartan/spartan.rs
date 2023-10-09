use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;
use std::marker::PhantomData;

use crate::{
    r1cs::R1CS,
    timer::{profiler_end, profiler_start},
    ScalarField,
};

use crate::spartan::{
    hyrax::Hyrax,
    polynomial::eq_poly::EqPoly,
    sumcheck::{sumcheck::verify_sum, SumCheckPhase1, SumCheckPhase2},
    transcript::Transcript,
};

use super::{
    hyrax::{PolyEvalProof, PolyEvalProofInters},
    ipa::IPAInters,
    polynomial::sparse_ml_poly::SparseMLPoly,
    sumcheck::{sumcheck::init_blinder_poly, SumCheckProof},
};

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct SpartanProof<C: CurveGroup> {
    pub pub_input: Vec<ScalarField<C>>,
    pub sc_proof_1: SumCheckProof<C>,
    pub sc_proof_2: SumCheckProof<C>,
    pub z_eval_proof: PolyEvalProof<C>,
    pub v_A: ScalarField<C>,
    pub v_B: ScalarField<C>,
    pub v_C: ScalarField<C>,
}

pub struct SpartanVerifyInters<C: CurveGroup> {
    pub sc1_inters: IPAInters<C>,
    pub sc2_inters: IPAInters<C>,
    pub z_eval_inters: PolyEvalProofInters<C>,
}

pub struct Spartan<C: CurveGroup> {
    pub hyrax: Hyrax<C>,
    _marker: PhantomData<C>,
}

impl<C: CurveGroup> Spartan<C> {
    // n: the length of the z vector
    pub fn new(n: usize) -> Self {
        // Generators are use in Hyrax for committing the witness polynomial,
        // and two IPAs for committing the blinder polynomials.
        // We prepare generators with size sufficient to conduct the
        // above commitments.

        let m = (n as f64).log2() as usize;

        // The blinder polynomial in the first sumcheck
        // has 4m + 1 coefficients.
        let num_bases = std::cmp::max((4 * m + 1).next_power_of_two(), Hyrax::<C>::det_num_rows(n));

        let hyrax = Hyrax::new(n, num_bases);

        Self {
            hyrax,
            _marker: PhantomData,
        }
    }

    pub fn prove(
        &self,
        r1cs: &R1CS<ScalarField<C>>,
        r1cs_witness: &[ScalarField<C>],
        r1cs_input: &[ScalarField<C>],
        transcript: &mut Transcript<C>,
    ) -> (SpartanProof<C>, Vec<ScalarField<C>>) {
        // Multilinear extension requires the number of evaluations
        // to be a power of two to uniquely determine the polynomial
        let mut padded_r1cs_witness = r1cs_witness.to_vec();
        padded_r1cs_witness.resize(
            padded_r1cs_witness.len().next_power_of_two(),
            ScalarField::<C>::ZERO,
        );

        let Z = R1CS::construct_z(r1cs_witness, r1cs_input);

        // Commit the witness polynomial
        let comm_witness_timer = profiler_start("Commit witness");
        let mut rng = thread_rng();
        let blinder = ScalarField::<C>::rand(&mut rng);
        let committed_witness = self.hyrax.commit(padded_r1cs_witness.clone(), blinder);
        profiler_end(comm_witness_timer);

        // Add the witness commitment to the transcript
        transcript.append_points(&committed_witness.T);

        // ############################
        // Phase 1
        // ###################

        let m = (r1cs.z_len() as f64).log2() as usize;

        let mut Az_poly = r1cs.A.mul_vector(&Z);
        let mut Bz_poly = r1cs.B.mul_vector(&Z);
        let mut Cz_poly = r1cs.C.mul_vector(&Z);

        Az_poly.resize(Z.len(), ScalarField::<C>::ZERO);
        Bz_poly.resize(Z.len(), ScalarField::<C>::ZERO);
        Cz_poly.resize(Z.len(), ScalarField::<C>::ZERO);

        // Prove that the
        // Q(t) = \sum_{x \in {0, 1}^m} (Az_poly(x) * Bz_poly(x) - Cz_poly(x)) eq(t, x)
        // is a zero-polynomial using the sum-check protocol.
        // We evaluate Q(t) at $\tau$ and check that it is zero.

        let tau = transcript.challenge_scalars(m, b"tau");

        // We implement the zero-knowledge sumcheck protocol
        // described in Section 4.1 https://eprint.iacr.org/2019/317.pdf
        let init_blinder_poly_timer = profiler_start("Init blinder poly");
        let (sc1_blinder_poly, sc1_blinder_poly_comm) =
            init_blinder_poly(m, 3, &self.hyrax, transcript);
        profiler_end(init_blinder_poly_timer);

        let sc_phase_1_timer = profiler_start("Sumcheck phase 1");

        let sc_phase_1 = SumCheckPhase1::new(Az_poly.clone(), Bz_poly.clone(), Cz_poly.clone());
        let (sc_proof_1, (v_A, v_B, v_C), rx) = sc_phase_1.prove(
            &self.hyrax,
            tau,
            sc1_blinder_poly.sum,
            sc1_blinder_poly,
            &sc1_blinder_poly_comm,
            transcript,
        );

        profiler_end(sc_phase_1_timer);

        transcript.append_scalar(v_A);
        transcript.append_scalar(v_B);
        transcript.append_scalar(v_C);

        // Phase 2
        let r = transcript.challenge_scalars(3, b"r");

        // T_2 should equal teh evaluations of the random linear combined polynomials

        let sc_phase_2_timer = profiler_start("Sumcheck phase 2");
        let sc_phase_2 = SumCheckPhase2::new(
            r1cs.A.clone(),
            r1cs.B.clone(),
            r1cs.C.clone(),
            Z.clone(),
            rx.clone(),
            r.as_slice().try_into().unwrap(),
        );

        let (sc2_blinder_poly, sc2_blinder_poly_comm) =
            init_blinder_poly(m, 2, &self.hyrax, transcript);

        let (sc_proof_2, ry) = sc_phase_2.prove(
            &self.hyrax,
            sc2_blinder_poly.sum,
            sc2_blinder_poly,
            &sc2_blinder_poly_comm,
            transcript,
        );

        profiler_end(sc_phase_2_timer);

        let z_open_timer = profiler_start("Open witness poly");
        // Prove the evaluation of the polynomial Z(y) at ry
        let z_eval_proof = self
            .hyrax
            .open(&committed_witness, ry[1..].to_vec(), transcript);
        profiler_end(z_open_timer);

        // Prove the evaluation of the polynomials A(y), B(y), C(y) at ry

        let rx_ry = vec![ry, rx].concat();
        (
            SpartanProof {
                pub_input: r1cs_input.to_vec(),
                sc_proof_1,
                sc_proof_2,
                z_eval_proof,
                v_A,
                v_B,
                v_C,
            },
            rx_ry,
        )
    }

    pub fn verify(
        &self,
        r1cs: &R1CS<ScalarField<C>>,
        proof: &SpartanProof<C>,
        transcript: &mut Transcript<C>,
        compute_inters: bool,
    ) -> Option<SpartanVerifyInters<C>> {
        transcript.append_points(&proof.z_eval_proof.T);

        let A_mle = r1cs.A.to_ml_extension();
        let B_mle = r1cs.B.to_ml_extension();
        let C_mle = r1cs.C.to_ml_extension();

        let m = (r1cs.z_len() as f64).log2() as usize;

        // ############################
        // Verify phase 1 sumcheck
        // ############################

        let tau = transcript.challenge_scalars(m, b"tau");

        let sc_phase1_sum_target = ScalarField::<C>::ZERO;

        // The final eval should equal
        let v_A = proof.v_A;
        let v_B = proof.v_B;
        let v_C = proof.v_C;

        let T_1_eq = EqPoly::new(tau);

        let sc_phase1_poly =
            |challenge: &[ScalarField<C>]| (v_A * v_B - v_C) * T_1_eq.eval(challenge);

        let (sc1_inters, rx) = verify_sum(
            &proof.sc_proof_1,
            &self.hyrax,
            sc_phase1_sum_target,
            sc_phase1_poly,
            3,
            transcript,
            b"sc_phase_1",
            compute_inters,
        );

        // ############################
        // Verify phase 2 sumcheck
        // ############################

        transcript.append_scalar(v_A);
        transcript.append_scalar(v_B);
        transcript.append_scalar(v_C);

        let r = transcript.challenge_scalars(3, b"r");
        let r_A = r[0];
        let r_B = r[1];
        let r_C = r[2];

        let sc_phase2_sum_target = r_A * v_A + r_B * v_B + r_C * v_C;

        let sc_phase2_poly = |ry: &[ScalarField<C>]| {
            let rx_ry = [&rx, ry].concat();
            let witness_eval = proof.z_eval_proof.inner_prod_proof.y;

            let eval_timer = profiler_start("Eval R1CS");
            let A_eval = A_mle.eval_naive(&rx_ry);
            let B_eval = B_mle.eval_naive(&rx_ry);
            let C_eval = C_mle.eval_naive(&rx_ry);
            profiler_end(eval_timer);

            let input = (0..r1cs.num_input)
                .map(|i| (i + 1, proof.pub_input[i]))
                .collect::<Vec<(usize, ScalarField<C>)>>();

            let input_poly = SparseMLPoly::new(
                vec![vec![(0, ScalarField::<C>::ONE)], input].concat(),
                ry.len() - 1,
            );
            let input_poly_eval = input_poly.eval(&ry[1..]);

            let z_eval = (ScalarField::<C>::ONE - ry[0]) * input_poly_eval + ry[0] * witness_eval;

            let eval = (r_A * A_eval + r_B * B_eval + r_C * C_eval) * z_eval;

            eval
        };

        let (sc2_inters, _) = verify_sum(
            &proof.sc_proof_2,
            &self.hyrax,
            sc_phase2_sum_target,
            sc_phase2_poly,
            2,
            transcript,
            b"sc_phase_2",
            compute_inters,
        );

        let pcs_verify_timer = profiler_start("Verify PCS");
        let z_eval_inters = self
            .hyrax
            .verify(&proof.z_eval_proof, transcript, compute_inters);
        profiler_end(pcs_verify_timer);

        if compute_inters {
            Some(SpartanVerifyInters {
                sc1_inters: sc1_inters.unwrap(),
                sc2_inters: sc2_inters.unwrap(),
                z_eval_inters: z_eval_inters.unwrap(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::{
        constraint_system::ConstraintSystem,
        frontend::test_utils::mock_circuit,
        timer::{timer_end, timer_start},
    };

    type Curve = ark_secq256k1::Projective;
    type F = ark_secq256k1::Fr;

    #[test]
    fn test_spartan() {
        let num_cons = 2usize.pow(10);

        let synthesizer = mock_circuit(num_cons);
        let mut cs = ConstraintSystem::new();
        cs.set_constraints(&synthesizer);
        let r1cs = cs.to_r1cs();

        let priv_input = vec![F::from(1), F::from(2)];
        let pub_input = [priv_input[0] * priv_input[1]];

        let witness = cs.gen_witness(&synthesizer, &pub_input, &priv_input);

        let spartan = Spartan::<Curve>::new(r1cs.z_len());
        let mut prover_transcript = Transcript::new(b"test_spartan");
        let proof_gen_timer = timer_start("Prove");
        let (proof, _) = spartan.prove(&r1cs, &witness, &pub_input, &mut prover_transcript);

        timer_end(proof_gen_timer);

        let mut verifier_transcript = Transcript::new(b"test_spartan");
        let proof_verify_timer = timer_start("Verify");
        let _inters = spartan
            .verify(&r1cs, &proof, &mut verifier_transcript, true)
            .unwrap();

        timer_end(proof_verify_timer);
    }
}
