use super::SumCheckProof;
use crate::spartan::hyrax::Hyrax;
use crate::spartan::ipa::{IPAComm, IPAInters};
use crate::spartan::sumcheck::unipoly::UniPoly;
use crate::spartan::transcript::Transcript;
use crate::timer::{profiler_end, profiler_start};
use crate::ScalarField;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, UniformRand};

#[derive(Clone)]
pub struct BlinderPoly<F: PrimeField> {
    pub uni_polys: Vec<UniPoly<F>>,
    pub evals: Vec<F>, // Evaluation over the boolean hypercube
    pub sum: F,
}

impl<F: PrimeField> BlinderPoly<F> {
    pub fn new(coeffs: Vec<Vec<F>>) -> Self {
        let num_vars = coeffs.len();
        let uni_polys = coeffs
            .iter()
            .map(|coeffs| UniPoly::new(coeffs.clone()))
            .collect::<Vec<UniPoly<F>>>();

        let num_evals = 2usize.pow(num_vars as u32);

        let evals = (0..num_evals)
            .map(|x| {
                let mut eval = F::ZERO;
                let mut x = x;

                for uni_poly in uni_polys.iter().rev() {
                    eval += uni_poly.eval_binary(x & 1 == 1);
                    x >>= 1;
                }

                eval
            })
            .collect::<Vec<F>>();

        let sum = evals.iter().fold(F::ZERO, |acc, x| acc + *x);

        Self {
            uni_polys,
            evals,
            sum,
        }
    }

    pub fn eval_point_powers(poly_degree: usize, x: &[F]) -> Vec<F> {
        let mut b = vec![];

        for x_i in x {
            let mut powers = vec![];
            let mut c_pow = F::ONE;

            for _ in 0..(poly_degree + 1) {
                powers.push(c_pow);
                c_pow *= *x_i;
            }

            powers.reverse();
            b.push(powers);
        }

        b.iter().flatten().map(|x| *x).collect::<Vec<F>>()
    }
}

pub fn init_blinder_poly<C: CurveGroup>(
    num_vars: usize,
    poly_degree: usize,
    hyrax: &Hyrax<C>,
    transcript: &mut Transcript<C>,
) -> (BlinderPoly<ScalarField<C>>, IPAComm<C>) {
    // We implement the zero-knowledge sumcheck protocol
    // described in Section 4.1 https://eprint.iacr.org/2019/317.pdf

    let mut rng = rand::thread_rng();

    // Sample a blinding polynomial g(x_1, ..., x_m)

    // The coefficients are stored from high to low degree.
    let random_coeffs = (0..num_vars)
        .map(|_| {
            (0..(poly_degree + 1))
                .map(|_| ScalarField::<C>::rand(&mut rng))
                .collect::<Vec<ScalarField<C>>>()
        })
        .collect::<Vec<Vec<ScalarField<C>>>>();

    let mut random_coeffs_flat = random_coeffs
        .iter()
        .flatten()
        .map(|x| *x)
        .collect::<Vec<ScalarField<C>>>();

    random_coeffs_flat.resize(
        random_coeffs_flat.len().next_power_of_two(),
        ScalarField::<C>::ZERO,
    );

    let blinder_poly = BlinderPoly::new(random_coeffs.clone());

    // Commit to the blinder polynomial
    let blinder = ScalarField::<C>::rand(&mut rng);
    let commit_b_timer = profiler_start("Commit blinder polynomial");
    let blinder_poly_comm = hyrax.ipa.commit(random_coeffs_flat, blinder);
    profiler_end(commit_b_timer);

    // Append the sum and the commitment of the blinder polynomial to the transcript.
    transcript.append_scalar(blinder_poly.sum);
    transcript.append_point(blinder_poly_comm.comm);

    (blinder_poly, blinder_poly_comm)
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
    hyrax: &Hyrax<C>,
    blinder_poly_sum: ScalarField<C>,
    blinder_poly: BlinderPoly<ScalarField<C>>,
    blinder_poly_comm: &IPAComm<C>,
    transcript: &mut Transcript<C>,
    label: &'static [u8],
) -> (SumCheckProof<C>, Vec<ScalarField<C>>) {
    let num_tables = eval_tables.len();
    let mut round_polys = Vec::<UniPoly<ScalarField<C>>>::with_capacity(poly_num_vars);

    let rho = transcript.challenge_scalar(label);

    let challenge = transcript.challenge_scalars(poly_num_vars, label);

    let round_poly_domain = (0..(poly_degree + 1)).map(|i| i).collect::<Vec<usize>>();

    let sc_timer = profiler_start("Sumcheck");
    for j in 0..poly_num_vars {
        let high_index = 2usize.pow((poly_num_vars - j - 1) as u32);
        let mut evals = vec![ScalarField::<C>::ZERO; poly_degree + 1];

        let mut bounded_eval = ScalarField::<C>::ZERO;
        for (l, uni_poly) in blinder_poly.uni_polys[..j].iter().enumerate() {
            bounded_eval += uni_poly.eval(challenge[l]);
        }

        // https://eprint.iacr.org/2019/317.pdf#subsection.3.2
        for b in 0..high_index {
            let r_y_i = challenge[j];

            // Cache the calculation
            let table_tmp = eval_tables
                .iter()
                .map(|table| (table[b + high_index] - table[b]))
                .collect::<Vec<ScalarField<C>>>();

            for (i, eval_at) in round_poly_domain.iter().enumerate() {
                let mut comb_input = Vec::with_capacity(num_tables);

                for (table, tmp) in eval_tables.iter().zip(table_tmp.iter()) {
                    let table_eval = if *eval_at == 0 {
                        table[b]
                    } else if *eval_at == 1 {
                        table[b] + tmp
                    } else if *eval_at == 2 {
                        table[b] + tmp + tmp
                    } else {
                        table[b] + tmp + tmp + tmp
                    };

                    comb_input.push(table_eval);
                }

                if !comb_input.iter().all(|x| *x == ScalarField::<C>::ZERO) {
                    evals[i] += comb_func(&comb_input);
                }

                let mut blinder_eval = bounded_eval;
                blinder_eval += blinder_poly.uni_polys[j].eval_small(*eval_at);
                for (l, uni_poly) in blinder_poly.uni_polys[(j + 1)..].iter().enumerate() {
                    blinder_eval += uni_poly.eval_binary((b >> l) & 1 == 1);
                }

                evals[i] += rho * blinder_eval;
            }

            for table in eval_tables.into_iter() {
                table[b] = table[b] + (table[b + high_index] - table[b]) * r_y_i;
            }
        }

        let round_poly = UniPoly::interpolate(&evals);
        round_polys.push(round_poly);
    }

    profiler_end(sc_timer);

    let open_blinder_poly_profiler = profiler_start("Open blinder poly");
    // Compute the domain which inner product will be the evaluation of the blinder polynomial

    let mut b = BlinderPoly::eval_point_powers(poly_degree, &challenge);
    b.resize(b.len().next_power_of_two(), ScalarField::<C>::ZERO);

    let blinder_poly_eval_proof = hyrax.ipa.open(&blinder_poly_comm, b, transcript);

    profiler_end(open_blinder_poly_profiler);

    (
        SumCheckProof {
            blinder_poly_sum,
            round_poly_coeffs: round_polys
                .iter()
                .map(|p| p.coeffs.clone())
                .collect::<Vec<Vec<ScalarField<C>>>>(),
            blinder_poly_eval_proof,
        },
        challenge,
    )
}

// Evaluates all the round polynomials at the challenge point,
// and returns the evaluation of the last round polynomial.
pub fn verify_sum<C: CurveGroup>(
    proof: &SumCheckProof<C>,
    hyrax: &Hyrax<C>,
    sum_target: ScalarField<C>,
    poly: impl Fn(&[ScalarField<C>]) -> ScalarField<C>,
    poly_degree: usize,
    transcript: &mut Transcript<C>,
    label: &'static [u8],
    compute_inters: bool,
) -> (Option<IPAInters<C>>, Vec<ScalarField<C>>) {
    // Append the sum and the commitment to the blinder polynomial to the transcript.
    transcript.append_scalar(proof.blinder_poly_sum);
    transcript.append_point(proof.blinder_poly_eval_proof.comm);

    // Get the challenge to combine the blinder polynomial with the summed polynomial(s).
    let rho = transcript.challenge_scalar(label);

    // Get challenges for each round of the sumcheck protocol.
    let poly_num_vars = proof.round_poly_coeffs.len();
    let challenge = transcript.challenge_scalars(poly_num_vars, label);

    // Verify the validity of the round polynomials.
    let mut target = sum_target + rho * proof.blinder_poly_sum;
    //  let mut target = sum_target;

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

    let poly_eval = (poly)(&challenge) + rho * proof.blinder_poly_eval_proof.y;

    assert_eq!(poly_eval, target);

    let mut b = BlinderPoly::eval_point_powers(poly_degree, &challenge);
    b.resize(b.len().next_power_of_two(), ScalarField::<C>::ZERO);

    (
        hyrax.ipa.verify(
            &proof.blinder_poly_eval_proof,
            b,
            transcript,
            compute_inters,
        ),
        challenge,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spartan::polynomial::ml_poly::MlPoly;
    use ark_ff::Field;

    type Curve = ark_secq256k1::Projective;
    type Fp = ark_secq256k1::Fr;

    #[test]
    fn test_sumcheck() {
        let poly_num_vars = 5;
        let poly_num_entries = 2usize.pow(poly_num_vars as u32);
        let poly_degree = 3;
        let mut prover_transcript = Transcript::<Curve>::new(b"test_sumcheck");
        let mut verifier_transcript = prover_transcript.clone();

        let hyrax = Hyrax::new(poly_num_entries, poly_num_entries);

        let eval_table_1 = (0..poly_num_entries)
            .map(|i| Fp::from((i + 333) as u64))
            .collect::<Vec<Fp>>();

        let eval_table_2 = (0..poly_num_entries)
            .map(|i| Fp::from((i + 23) as u64))
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

        let poly_1 = MlPoly::new(eval_table_1);
        let poly_2 = MlPoly::new(eval_table_2);
        let poly_3 = MlPoly::new(eval_table_3);

        let poly = |x: &[Fp]| (poly_1.eval(x) * poly_2.eval(x)) - poly_3.eval(x);
        let comb_func = |x: &[Fp]| (x[0] * x[1]) - x[2];

        let mut sum_target = Fp::ZERO;

        for i in 0..poly_num_entries {
            let x_0 = eval_tables[0][i];
            let x_1 = eval_tables[1][i];
            let x_2 = eval_tables[2][i];
            let term = comb_func(&[x_0, x_1, x_2]);
            sum_target += term;
        }

        let sumcheck_prove_timer = profiler_start("Sumcheck prove");
        let (blinder_poly, blinder_poly_comm) =
            init_blinder_poly(poly_num_vars, poly_degree, &hyrax, &mut prover_transcript);

        let label = b"test_sumcheck";
        let (sumcheck_proof, _) = prove_sum(
            poly_num_vars,
            poly_degree,
            &mut eval_tables,
            comb_func,
            &hyrax,
            blinder_poly.sum,
            blinder_poly,
            &blinder_poly_comm,
            &mut prover_transcript,
            label,
        );
        profiler_end(sumcheck_prove_timer);

        verify_sum(
            &sumcheck_proof,
            &hyrax,
            sum_target,
            poly,
            poly_degree,
            &mut verifier_transcript,
            label,
            false,
        );
    }
}
