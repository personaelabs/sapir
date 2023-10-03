use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand};

use crate::spartan::hyrax::{Hyrax, HyraxComm, PolyEvalProofInters};
use crate::spartan::polynomial::ml_poly::MlPoly;
use crate::spartan::sumcheck::unipoly::UniPoly;
use crate::spartan::transcript::Transcript;
use crate::timer::{profiler_end, profiler_start};
use crate::ScalarField;

use super::SumCheckProof;

fn init_blinder_poly<C: CurveGroup>(
    num_vars: usize,
    bp: &Hyrax<C>,
    transcript: &mut Transcript<C>,
) -> (MlPoly<ScalarField<C>>, HyraxComm<C>, ScalarField<C>) {
    // We implement the zero-knowledge sumcheck protocol
    // described in Section 4.1 https://eprint.iacr.org/2019/317.pdf

    let mut rng = rand::thread_rng();
    // Sample a blinding polynomial g(x_1, ..., x_m)
    let blinder_poly_evals = (0..2usize.pow(num_vars as u32))
        .map(|_| ScalarField::<C>::rand(&mut rng))
        .collect::<Vec<ScalarField<C>>>();
    let blinder_poly = MlPoly::new(blinder_poly_evals.clone());
    let blinder_poly_sum = blinder_poly_evals
        .iter()
        .fold(ScalarField::<C>::ZERO, |acc, x| acc + x);

    let blinder = ScalarField::<C>::rand(&mut rng);
    let commit_b_timer = profiler_start("Commit blinder polynomial");
    let blinder_poly_comm = bp.commit(blinder_poly_evals, blinder);
    profiler_end(commit_b_timer);

    transcript.append_fe(blinder_poly_sum);
    transcript.append_points(&blinder_poly_comm.T);

    (blinder_poly, blinder_poly_comm, blinder_poly_sum)
}

fn challenge_label(label: String) -> String {
    format!("{}-challenge", label)
}

fn rho_label(label: String) -> String {
    format!("{}-rho", label)
}

// This function implements the zero-knowledge sumcheck protocol, and
// is agnostic of the polynomial(s) being summed.
// The function caller must provide the polynomial(s)'s evaluation tables,
// and the function that combines the evaluation tables (i.e. combines the evaluations of polynomials).

// Transcript behavior:
// 1. Append the sum and the commitment to the blinder polynomial.
// 2. Gets a challenge to combine the blinder polynomial with the summed polynomial(s).
// 3. Gets challenges for each round of the sumcheck protocol.

pub fn prove_sum<C: CurveGroup>(
    poly_num_vars: usize,
    poly_degree: usize,
    eval_tables: &mut Vec<Vec<ScalarField<C>>>,
    comb_func: impl Fn(&[ScalarField<C>]) -> ScalarField<C>,
    pcs: &Hyrax<C>,
    transcript: &mut Transcript<C>,
    label: String,
) -> SumCheckProof<C> {
    let num_tables = eval_tables.len();
    let mut round_polys = Vec::<UniPoly<ScalarField<C>>>::with_capacity(poly_num_vars);

    // We implement the zero-knowledge sumcheck protocol
    // described in Section 4.1 https://eprint.iacr.org/2019/317.pdf
    let (blinder_poly, blinder_poly_comm, blinder_poly_sum) =
        init_blinder_poly(poly_num_vars, pcs, transcript);

    let mut blinder_table = blinder_poly.evals.clone();

    let rho = transcript.challenge_fe(rho_label(label.clone()));

    let challenge = transcript.challenge_vec(poly_num_vars, challenge_label(label.clone()));

    let round_poly_domain = (0..(poly_degree + 1))
        .map(|i| ScalarField::<C>::from(i as u64))
        .collect::<Vec<ScalarField<C>>>();

    let sc_timer = profiler_start("Sumcheck");
    for j in 0..poly_num_vars {
        let high_index = 2usize.pow((poly_num_vars - j - 1) as u32);
        let mut evals = vec![ScalarField::<C>::ZERO; poly_degree + 1];

        // https://eprint.iacr.org/2019/317.pdf#subsection.3.2
        for b in 0..high_index {
            let r_y_i = challenge[j];
            for (i, eval_at) in round_poly_domain.iter().enumerate() {
                let mut comb_input = Vec::with_capacity(num_tables);
                for table in eval_tables.into_iter() {
                    let table_eval = table[b] + (table[b + high_index] - table[b]) * eval_at;
                    comb_input.push(table_eval);
                }

                evals[i] += comb_func(&comb_input);
            }

            for table in eval_tables.into_iter() {
                table[b] = table[b] + (table[b + high_index] - table[b]) * r_y_i;
            }
        }

        for b in 0..high_index {
            let r_y_i = challenge[j];
            for (i, eval_at) in round_poly_domain.iter().enumerate() {
                let blinder_eval =
                    blinder_table[b] + (blinder_table[b + high_index] - blinder_table[b]) * eval_at;
                evals[i] += rho * blinder_eval;
            }

            blinder_table[b] =
                blinder_table[b] + (blinder_table[b + high_index] - blinder_table[b]) * r_y_i;
        }

        let round_poly = UniPoly::interpolate(&evals);
        round_polys.push(round_poly);
    }

    profiler_end(sc_timer);

    let blinder_poly_eval_proof = pcs.open(&blinder_poly_comm, challenge, transcript);

    SumCheckProof {
        label: label.to_string(),
        blinder_poly_sum,
        round_poly_coeffs: round_polys
            .iter()
            .map(|p| p.coeffs.clone())
            .collect::<Vec<Vec<ScalarField<C>>>>(),
        blinder_poly_eval_proof,
    }
}

// Evaluates all the round polynomials at the challenge point,
// and returns the evaluation of the last round polynomial.
pub fn verify_sum<C: CurveGroup>(
    proof: &SumCheckProof<C>,
    bp: &Hyrax<C>,
    sum_target: ScalarField<C>,
    poly: impl Fn(&[ScalarField<C>]) -> ScalarField<C>,
    transcript: &mut Transcript<C>,
    compute_inters: bool,
) -> Option<PolyEvalProofInters<C>> {
    // Append the sum and the commitment to the blinder polynomial to the transcript.
    transcript.append_fe(proof.blinder_poly_sum);
    transcript.append_points(&proof.blinder_poly_eval_proof.T);

    // Get the challenge to combine the blinder polynomial with the summed polynomial(s).
    let rho = transcript.challenge_fe(rho_label(proof.label.clone()));

    // Get challenges for each round of the sumcheck protocol.
    let poly_num_vars = proof.round_poly_coeffs.len();
    let challenge = transcript.challenge_vec(poly_num_vars, challenge_label(proof.label.clone()));

    // Verify the validity of the round polynomials.
    let mut target = sum_target + rho * proof.blinder_poly_sum;

    for (i, coeffs) in proof.round_poly_coeffs.iter().enumerate() {
        let round_poly = UniPoly::new(coeffs.clone());
        assert_eq!(
            round_poly.eval(ScalarField::<C>::ZERO) + round_poly.eval(ScalarField::<C>::ONE),
            target,
            "i = {}",
            i
        );

        target = round_poly.eval(challenge[i]);
    }

    // Verify the opening of the blinder polynomial.

    let poly_eval = (poly)(&challenge) + rho * proof.blinder_poly_eval_proof.inner_prod_proof.y;

    assert_eq!(poly_eval, target);

    bp.verify(&proof.blinder_poly_eval_proof, transcript, compute_inters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    type Curve = ark_secq256k1::Projective;
    type Fp = ark_secq256k1::Fr;

    #[test]
    fn test_sumcheck() {
        let poly_num_vars = 8;
        let poly_num_entries = 2usize.pow(poly_num_vars as u32);
        let poly_degree = 2;
        let mut prover_transcript = Transcript::<Curve>::new(b"test_sumcheck");
        let mut verifier_transcript = prover_transcript.clone();

        let bp = Hyrax::new(poly_num_entries);

        let eval_table_1 = (0..poly_num_entries)
            .map(|i| Fp::from(i as u64))
            .collect::<Vec<Fp>>();

        let eval_table_2 = (0..poly_num_entries)
            .map(|i| Fp::from(i as u64))
            .collect::<Vec<Fp>>();

        let eval_table_3 = eval_table_1
            .iter()
            .zip(eval_table_2.iter())
            .map(|(x, y)| x * y)
            .collect::<Vec<Fp>>();

        let mut eval_tables = vec![
            eval_table_1.clone(),
            eval_table_2.clone(),
            eval_table_3.clone(),
        ];

        let comb_func = |x: &[Fp]| x[0] * x[1] - x[2];

        let sumcheck_prove_timer = profiler_start("Sumcheck prove");
        let sumcheck_proof = prove_sum(
            poly_num_vars,
            poly_degree,
            &mut eval_tables,
            comb_func,
            &bp,
            &mut prover_transcript,
            "test_sumcheck".to_string(),
        );
        profiler_end(sumcheck_prove_timer);

        let poly_1 = MlPoly::new(eval_table_1);
        let poly_2 = MlPoly::new(eval_table_2);
        let poly_3 = MlPoly::new(eval_table_3);

        let poly = |x: &[Fp]| poly_1.eval(x) * poly_2.eval(x) - poly_3.eval(x);

        let sum_target = Fp::ZERO;
        verify_sum(
            &sumcheck_proof,
            &bp,
            sum_target,
            poly,
            &mut verifier_transcript,
            false,
        );
    }
}
