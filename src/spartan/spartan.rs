use super::{
    hyrax::PolyEvalProof,
    polynomial::sparse_ml_poly::SparseMLPoly,
    sumcheck::{sumcheck::init_blinder_poly, SumCheckProof},
};
use crate::spartan::{
    hyrax::Hyrax,
    polynomial::eq_poly::EqPoly,
    sumcheck::{sumcheck::verify_sum, SumCheckPhase1, SumCheckPhase2},
    transcript::Transcript,
};
use crate::{
    r1cs::R1CS,
    timer::{profiler_end, profiler_start},
    ScalarField,
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct SpartanProof<C: CurveGroup> {
    pub pub_input: Vec<ScalarField<C>>,
    pub sc_proof_1: SumCheckProof<C>,
    pub sc_proof_2: SumCheckProof<C>,
    pub witness_eval_proof: PolyEvalProof<C>,
    pub v_A: ScalarField<C>,
    pub v_B: ScalarField<C>,
    pub v_C: ScalarField<C>,
}

pub struct Spartan<C: CurveGroup> {
    pub label: &'static [u8],
    pub r1cs: R1CS<ScalarField<C>>,
    pub hyrax: Hyrax<C>,
}

impl<C: CurveGroup> Spartan<C> {
    pub fn new(label: &'static [u8], r1cs: R1CS<ScalarField<C>>) -> Self {
        let n = r1cs.num_vars.next_power_of_two();
        let m = (n as f64).log2() as usize;

        // The blinder polynomial in the first sumcheck
        // has 4m + 1 coefficients.
        let num_bases = std::cmp::max((4 * m + 1).next_power_of_two(), Hyrax::<C>::det_num_rows(n));

        let hyrax = Hyrax::new(n, num_bases);

        Self { label, r1cs, hyrax }
    }

    pub fn prove(
        &self,
        r1cs_witness: &[ScalarField<C>],
        r1cs_input: &[ScalarField<C>],
    ) -> (SpartanProof<C>, Vec<ScalarField<C>>) {
        let mut transcript = Transcript::new(self.label);

        // Pad the witness vector to make the length a power of two
        let mut padded_r1cs_witness = r1cs_witness.to_vec();
        padded_r1cs_witness.resize(
            padded_r1cs_witness.len().next_power_of_two(),
            ScalarField::<C>::ZERO,
        );

        // Construct the `Z` vector from the witness and input
        let Z = R1CS::construct_z(r1cs_witness, r1cs_input);
        // Commit the witness polynomial
        let comm_witness_timer = profiler_start("Commit witness");
        let committed_witness = self.hyrax.commit(padded_r1cs_witness);
        profiler_end(comm_witness_timer);

        // Add the witness commitment to the transcript
        transcript.append_points(b"T", &committed_witness.T);

        // ############################
        // Phase 1
        // ###################

        let m = (self.r1cs.z_len() as f64).log2() as usize;

        // Multiply the A, B, and C matrices with the Z vector
        let mut Az = self.r1cs.A.mul_vector(&Z);
        let mut Bz = self.r1cs.B.mul_vector(&Z);
        let mut Cz = self.r1cs.C.mul_vector(&Z);

        // Resize the vectors so we can apply the sumcheck
        Az.resize(Z.len(), ScalarField::<C>::ZERO);
        Bz.resize(Z.len(), ScalarField::<C>::ZERO);
        Cz.resize(Z.len(), ScalarField::<C>::ZERO);

        let tau = transcript.challenge_scalars(m, b"tau");

        // We implement the zero-knowledge sumcheck protocol
        // described in Section 4.1 https://eprint.iacr.org/2019/317.pdf.
        let init_blinder_poly_timer = profiler_start("Init blinder poly");
        let (sc1_blinder_poly, sc1_blinder_poly_comm) =
            init_blinder_poly(m, 3, &self.hyrax, &mut transcript);
        profiler_end(init_blinder_poly_timer);

        let sc_phase_1_timer = profiler_start("Sumcheck phase 1");

        let sc_phase_1 = SumCheckPhase1::new(Az, Bz, Cz);
        let (sc_proof_1, (v_A, v_B, v_C), rx) = sc_phase_1.prove(
            m,
            &self.hyrax,
            tau,
            sc1_blinder_poly.sum,
            sc1_blinder_poly,
            &sc1_blinder_poly_comm,
            &mut transcript,
        );

        profiler_end(sc_phase_1_timer);

        transcript.append_scalar(b"v_A", v_A);
        transcript.append_scalar(b"v_B", v_B);
        transcript.append_scalar(b"v_C", v_C);

        // Phase 2
        let r = transcript.challenge_scalars(3, b"r");

        let sc_phase_2_timer = profiler_start("Sumcheck phase 2");
        let sc_phase_2 = SumCheckPhase2::new(
            self.r1cs.A.clone(),
            self.r1cs.B.clone(),
            self.r1cs.C.clone(),
            Z.clone(),
            rx.clone(),
            r.as_slice().try_into().unwrap(),
        );

        let (sc2_blinder_poly, sc2_blinder_poly_comm) =
            init_blinder_poly(m, 2, &self.hyrax, &mut transcript);

        let (sc_proof_2, ry) = sc_phase_2.prove(
            &self.hyrax,
            sc2_blinder_poly.sum,
            sc2_blinder_poly,
            &sc2_blinder_poly_comm,
            &mut transcript,
        );

        profiler_end(sc_phase_2_timer);

        let z_open_timer = profiler_start("Open witness poly");

        // Prove the evaluation of the polynomial w(y) at ry[1..]
        let witness_eval_proof =
            self.hyrax
                .open(&committed_witness, ry[1..].to_vec(), &mut transcript);
        profiler_end(z_open_timer);

        // Prove the evaluation of the polynomials A(y), B(y), C(y) at ry

        let rx_ry = vec![ry, rx].concat();
        (
            SpartanProof {
                pub_input: r1cs_input.to_vec(),
                sc_proof_1,
                sc_proof_2,
                witness_eval_proof,
                v_A,
                v_B,
                v_C,
            },
            rx_ry,
        )
    }

    pub fn verify(&self, proof: &SpartanProof<C>) {
        let mut transcript = Transcript::new(self.label);
        transcript.append_points(b"T", &proof.witness_eval_proof.T);

        let A_mle = self.r1cs.A.to_ml_extension();
        let B_mle = self.r1cs.B.to_ml_extension();
        let C_mle = self.r1cs.C.to_ml_extension();

        let m = (self.r1cs.z_len() as f64).log2() as usize;

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

        let rx = verify_sum(
            &proof.sc_proof_1,
            &self.hyrax,
            sc_phase1_sum_target,
            sc_phase1_poly,
            3,
            &mut transcript,
            b"sc_phase_1",
        );

        // ############################
        // Verify phase 2 sumcheck
        // ############################

        transcript.append_scalar(b"v_A", v_A);
        transcript.append_scalar(b"v_B", v_B);
        transcript.append_scalar(b"v_C", v_C);

        let r = transcript.challenge_scalars(3, b"r");
        let r_A = r[0];
        let r_B = r[1];
        let r_C = r[2];

        let sc_phase2_sum_target = r_A * v_A + r_B * v_B + r_C * v_C;

        let sc_phase2_poly = |ry: &[ScalarField<C>]| {
            let rx_ry = [&rx, ry].concat();
            let witness_eval = proof.witness_eval_proof.inner_prod_proof.y;

            let eval_timer = profiler_start("Eval R1CS");
            let A_eval = A_mle.eval_naive(&rx_ry);
            let B_eval = B_mle.eval_naive(&rx_ry);
            let C_eval = C_mle.eval_naive(&rx_ry);
            profiler_end(eval_timer);

            let input = (0..self.r1cs.num_input)
                .map(|i| ((i + 1) as u64, proof.pub_input[i]))
                .collect::<Vec<(u64, ScalarField<C>)>>();

            let input_poly = SparseMLPoly::new(
                vec![vec![(0u64, ScalarField::<C>::ONE)], input].concat(),
                ry.len() - 1,
            );
            let input_poly_eval = input_poly.eval(&ry[1..]);

            let z_eval = (ScalarField::<C>::ONE - ry[0]) * input_poly_eval + ry[0] * witness_eval;

            let eval = (r_A * A_eval + r_B * B_eval + r_C * C_eval) * z_eval;

            eval
        };

        let _ = verify_sum(
            &proof.sc_proof_2,
            &self.hyrax,
            sc_phase2_sum_target,
            sc_phase2_poly,
            2,
            &mut transcript,
            b"sc_phase_2",
        );

        let pcs_verify_timer = profiler_start("Verify PCS");
        self.hyrax
            .verify(&proof.witness_eval_proof, &mut transcript);
        profiler_end(pcs_verify_timer);
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
        let num_cons = 2usize.pow(4);

        let synthesizer = mock_circuit(num_cons);
        let mut cs = ConstraintSystem::new();
        cs.set_constraints(&synthesizer);
        let r1cs = cs.to_r1cs();

        let priv_input = vec![F::from(1), F::from(2)];
        let pub_input = [priv_input[0] * priv_input[1]];

        let witness = cs.gen_witness(&synthesizer, &pub_input, &priv_input);

        let spartan = Spartan::<Curve>::new(b"test_spartan", r1cs);
        let proof_gen_timer = timer_start("Prove");
        let (proof, _) = spartan.prove(&witness, &pub_input);
        timer_end(proof_gen_timer);

        // Verify a valid proof

        let proof_verify_timer = timer_start("Verify");
        spartan.verify(&proof);

        timer_end(proof_verify_timer);

        /*
        // Verify an invalid proof

        let mut invalid_proof = proof;
        invalid_proof.pub_input[0] += F::ONE;

        let result = panic::catch_unwind(|| {
            let mut verifier_transcript = Transcript::new(b"test_spartan");
            spartan.verify(&r1cs, &invalid_proof, &mut verifier_transcript, true);
        });

        assert!(result.is_err(), "Should assert invalid public input");
         */
    }
}
