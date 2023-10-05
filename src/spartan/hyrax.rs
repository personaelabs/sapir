use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    spartan::transcript::Transcript,
    spartan::{
        ipa::Bulletproof,
        polynomial::eq_poly::EqPoly,
        utils::{inner_prod, msm_powers},
    },
    spartan::{
        ipa::{IPAComm, InnerProductProof},
        utils::msm,
    },
    ScalarField,
};

use super::ipa::IPAInters;

pub struct HyraxComm<C: CurveGroup> {
    pub T: Vec<C>,
    pub w: Vec<Vec<ScalarField<C>>>,
    pub blinders: Vec<ScalarField<C>>,
}

#[derive(Clone)]
pub struct Hyrax<C: CurveGroup> {
    pub bp: Bulletproof<C>,
    padded_num_rows: usize,
    padded_num_cols: usize,
    padded_num_vrs: usize,
}

#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolyEvalProof<C: CurveGroup> {
    pub x: Vec<ScalarField<C>>,
    pub y: ScalarField<C>,
    pub T: Vec<C>,
    pub inner_prod_proof: InnerProductProof<C>,
}

// MSM intermediates that appear in the proof
#[derive(Clone)]
pub struct PolyEvalProofInters<C: CurveGroup> {
    pub T_prime_inters: Vec<C>,
    pub ipa_inters: IPAInters<C>,
}

impl<C: CurveGroup> Hyrax<C> {
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two());

        let mut n_padded_log2 = (n as f64).log2() as usize;

        // Make the number of rows power to the even number
        if n_padded_log2 & 1 == 1 {
            n_padded_log2 += 1;
        }
        let padded_num_rows = 2usize.pow((n_padded_log2 / 2) as u32);
        let padded_num_cols = padded_num_rows;
        assert_eq!(
            padded_num_rows * padded_num_cols,
            2usize.pow(n_padded_log2 as u32)
        );

        let bp = Bulletproof::new(std::cmp::max(padded_num_rows, padded_num_cols));
        Self {
            bp,
            padded_num_cols: padded_num_cols,
            padded_num_rows: padded_num_rows,
            padded_num_vrs: n_padded_log2,
        }
    }

    pub const fn empty() -> Self {
        Self {
            bp: Bulletproof::empty(),
            padded_num_cols: 0,
            padded_num_rows: 0,
            padded_num_vrs: 0,
        }
    }

    // Commit to a multilinear in polynomial `a` in evaluation form
    pub fn commit(&self, w: Vec<ScalarField<C>>, _blinder: ScalarField<C>) -> HyraxComm<C> {
        let mut w = w;
        w.resize(
            self.padded_num_rows * self.padded_num_cols,
            ScalarField::<C>::ZERO,
        );

        // In column-major order
        let mut w_rows = Vec::with_capacity(self.padded_num_cols);
        for col in 0..self.padded_num_cols {
            w_rows.push(w[col * self.padded_num_rows..(col + 1) * self.padded_num_rows].to_vec());
        }

        // let mut rng = ark_std::rand::thread_rng();
        let blinders = (0..w_rows.len())
            .map(|_| ScalarField::<C>::ZERO)
            .collect::<Vec<ScalarField<C>>>();

        let T = w_rows
            .iter()
            .zip(blinders.iter())
            .map(|(row, blinder)| self.bp.commit(row.to_vec(), *blinder).comm)
            .collect::<Vec<C>>();

        HyraxComm {
            T,
            w: w_rows,
            blinders,
        }
    }

    // Open the committed polynomial `comm_a`'s evaluation at `x`
    pub fn open(
        &self,
        comm_a: &HyraxComm<C>,
        x: Vec<ScalarField<C>>,
        transcript: &mut Transcript<C>,
    ) -> PolyEvalProof<C> {
        // Compute `L` and `R`

        // Pad `x`
        let mut x = x;
        let mut pad = vec![ScalarField::<C>::ZERO; self.padded_num_vrs - x.len()];
        // x.resize(self.padded_num_vrs, ScalarField::<C>::ZERO);
        pad.extend(x);
        x = pad;

        // TODO: Don't need to clone here
        let num_cols_log2 = (self.padded_num_cols as f64).log2() as usize;
        let num_rows_log2 = (self.padded_num_rows as f64).log2() as usize;
        let x_low = x[..num_cols_log2].to_vec();
        let x_high = x[num_rows_log2..].to_vec();
        let L = EqPoly::new(x_low).evals();
        let R = EqPoly::new(x_high.clone()).evals();

        assert_eq!(self.padded_num_cols, comm_a.w.len());

        // Compute w * L and construct an "augmented" committed polynomial
        // `comm_a_aug` that commits to `w * L`.
        // The verifier can trustlessly get this commitment.

        // Transpose and scale the vector
        let mut a_aug = vec![ScalarField::<C>::ZERO; self.padded_num_rows];
        for i in 0..self.padded_num_rows {
            for j in 0..self.padded_num_cols {
                a_aug[i] += comm_a.w[j][i] * L[j];
            }
        }

        let a_aug_C = msm(&L, &comm_a.T);

        let a_aug_comm = IPAComm {
            comm: a_aug_C,
            poly: a_aug.clone(),
            blinder: inner_prod(&comm_a.blinders, &L),
        };

        let inner_prod_proof = self.bp.open(&a_aug_comm, R, transcript);

        PolyEvalProof {
            x,
            y: inner_prod_proof.y,
            T: comm_a.T.clone(),
            inner_prod_proof,
        }
    }

    pub fn verify(
        &self,
        proof: &PolyEvalProof<C>,
        transcript: &mut Transcript<C>,
        compute_inters: bool,
    ) -> Option<PolyEvalProofInters<C>> {
        // Pad `x`
        let mut x = proof.x.clone();
        // x.resize(self.padded_num_vrs, ScalarField::<C>::ZERO);
        let mut pad = vec![ScalarField::<C>::ZERO; self.padded_num_vrs - x.len()];
        // x.resize(self.padded_num_vrs, ScalarField::<C>::ZERO);
        pad.extend(x);
        x = pad;

        let num_cols_log2 = (self.padded_num_cols as f64).log2() as usize;
        let num_rows_log2 = (self.padded_num_rows as f64).log2() as usize;
        let x_low = x[..num_cols_log2].to_vec();
        let x_high = x[num_rows_log2..].to_vec();
        let L = EqPoly::new(x_low).evals();
        let R = EqPoly::new(x_high).evals();

        assert_eq!(proof.inner_prod_proof.b, R);

        // Compute the intermediate powers of L * T
        let T_prime_inters = if compute_inters {
            msm_powers(&L, &proof.T)
        } else {
            vec![]
        };

        // Compute the commitment to the L * T
        let T_prime = msm(&L, &proof.T);
        assert_eq!(T_prime, proof.inner_prod_proof.comm);
        assert_eq!(x, proof.x);

        let bp_result = self
            .bp
            .verify(&proof.inner_prod_proof, transcript, compute_inters);

        if compute_inters {
            let ip_inters = bp_result.unwrap();
            Some(PolyEvalProofInters {
                T_prime_inters,
                ipa_inters: ip_inters,
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
        spartan::polynomial::ml_poly::MlPoly,
        timer::{timer_end, timer_start},
    };

    type F = ark_secq256k1::Fr;
    type Curve = ark_secq256k1::Projective;

    #[test]
    fn test_hyrax() {
        let m = 13;
        let n = 2usize.pow(m as u32);
        let a = (0..n).map(|i| F::from((i + 33) as u64)).collect::<Vec<F>>();
        let poly = MlPoly::new(a.clone());
        let x = (0..m).map(|i| F::from((i + 22) as u64)).collect::<Vec<F>>();
        let y = poly.eval(&x);

        let hyrax = Hyrax::<Curve>::new(n);
        let blinder = F::from(3);
        let comm_timer = timer_start("Commit");
        let comm = hyrax.commit(a, blinder);
        timer_end(comm_timer);

        let mut prover_transcript = Transcript::new(b"test");
        let open_timer = timer_start("Open");
        let eval_proof = hyrax.open(&comm, x.clone(), &mut prover_transcript);
        timer_end(open_timer);

        assert_eq!(eval_proof.y, y);

        let mut verifier_transcript = Transcript::new(b"test");
        hyrax.verify(&eval_proof, &mut verifier_transcript, false);
    }
}
