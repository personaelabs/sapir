use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    spartan::utils::{inner_prod, msm_powers},
    timer::{profiler_end, profiler_start},
    ScalarField,
};

use super::{commitment::Gens, transcript::Transcript, utils::msm};

#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct InnerProductProof<C: CurveGroup> {
    pub comm: C,
    pub b: Vec<ScalarField<C>>,
    pub y: ScalarField<C>,
    pub L_vec: Vec<C>,
    pub R_vec: Vec<C>,
    pub a: ScalarField<C>,
}

#[derive(Clone)]
pub struct IPAInters<C: CurveGroup> {
    pub sa_G_inters: Vec<C>,
    pub sb_H_inters: Vec<C>,
    pub b_H_inters: Vec<C>,
}

pub struct IPAComm<C: CurveGroup> {
    pub comm: C,
    // Evaluations of the polynomial
    pub poly: Vec<ScalarField<C>>,
}

#[derive(Clone)]
pub struct Bulletproof<C: CurveGroup> {
    pub gens: Gens<C>,
}

impl<C: CurveGroup> Bulletproof<C> {
    pub fn new(n: usize) -> Self {
        let gens = Gens::<C>::new(n);
        Self { gens }
    }

    pub const fn empty() -> Self {
        Self {
            gens: Gens {
                G: vec![],
                H: vec![],
                u: None,
            },
        }
    }

    fn hash(
        a: &[ScalarField<C>],
        a_prime: &[ScalarField<C>],
        b: &[ScalarField<C>],
        b_prime: &[ScalarField<C>],
        c: ScalarField<C>,
        gens: &Gens<C>,
    ) -> C {
        assert_eq!(a.len(), a_prime.len());
        assert_eq!(b.len(), b_prime.len());
        assert_eq!(a.len(), b.len());

        let a_G = msm(&[a, a_prime].concat(), &gens.G);
        let b_H = msm(&[b, b_prime].concat(), &gens.H);

        let c_u = gens.u.unwrap() * c;

        a_G + b_H + c_u
    }

    fn fold(
        a: &[ScalarField<C>],
        x_low: ScalarField<C>,
        x_high: ScalarField<C>,
    ) -> Vec<ScalarField<C>> {
        let n = a.len();
        let a_low = &a[..(n / 2)];
        let a_high = &a[(n / 2)..];

        a_low
            .iter()
            .zip(a_high.iter())
            .map(|(a_low, a_high)| *a_low * x_low + *a_high * x_high)
            .collect()
    }

    fn scale_points(p: &[C], s: ScalarField<C>) -> Vec<C> {
        p.iter().map(|p| *p * s).collect()
    }

    pub fn scale_vec(v: &[ScalarField<C>], s: ScalarField<C>) -> Vec<ScalarField<C>> {
        v.iter().map(|v| *v * s).collect()
    }

    fn hadamard(a: &[C], b: &[C]) -> Vec<C> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(a, b)| *a + *b).collect()
    }

    // Commit to the vector `a`
    pub fn commit(&self, a: Vec<ScalarField<C>>, _blinder: ScalarField<C>) -> IPAComm<C> {
        // TODO: Implement blinding
        let comm = msm(&a, &self.gens.G[..a.len()]);
        IPAComm { comm, poly: a }
    }

    pub fn open(
        &self,
        comm_a: &IPAComm<C>,
        b: Vec<ScalarField<C>>,
        transcript: &mut Transcript<C>,
    ) -> InnerProductProof<C> {
        let a = comm_a.poly.to_vec();
        let mut n = a.len();
        assert_eq!(n, b.len());

        // Compute the inner product <a, b>.
        // (i.e. the evaluation of the polynomial at `x`)
        let y = inner_prod(&a, &b);

        let mut a = a;
        let b_vec = b.clone();
        let mut b = b;
        let mut ck = self.gens.clone();

        let num_rounds = (n as f64).log2() as usize;

        let mut n_prime = n / 2;

        let mut L_vec = Vec::with_capacity(num_rounds);
        let mut R_vec = Vec::with_capacity(num_rounds);

        while n != 1 {
            let zero = ScalarField::<C>::ZERO;
            let zero_vec = vec![zero; n_prime];

            let a_L = &a[..n_prime];
            let b_L = &b[n_prime..];

            // L = hash(0, a_L, b_L, 0, <a_L, b_L>)
            let L = Self::hash(
                &zero_vec,
                a_L,
                b_L,
                &zero_vec,
                inner_prod::<ScalarField<C>>(a_L, b_L),
                &ck,
            );

            let a_R = &a[n_prime..];
            let b_R = &b[..n_prime];

            // R = hash(0, a_R, b_R, 0, <a_R, b_R>)
            let R_hash_profiler = profiler_start("R hash");
            let R = Self::hash(
                a_R,
                &zero_vec,
                &zero_vec,
                b_R,
                inner_prod::<ScalarField<C>>(a_R, b_R),
                &ck,
            );
            profiler_end(R_hash_profiler);

            L_vec.push(L);
            R_vec.push(R);

            // Append L and R into the transcript
            transcript.append_point(L);
            transcript.append_point(R);

            // Get the challenge `r`
            let r = transcript.challenge_fe("r".to_string());
            let r_inv = r.inverse().unwrap();

            // Fold a and b
            let a_folded = Self::fold(&a, r, r_inv);
            let b_folded = Self::fold(&b, r_inv, r);

            // Update the basis
            let g_low_prime = Self::scale_points(&ck.G[..n_prime], r_inv);
            let g_high_prime = Self::scale_points(&ck.G[n_prime..(n_prime * 2)], r);
            let g_prime = Self::hadamard(&g_low_prime, &g_high_prime);

            let h_low_prime = Self::scale_points(&ck.H[..n_prime], r);
            let h_high_prime = Self::scale_points(&ck.H[n_prime..(n_prime * 2)], r_inv);
            let h_prime = Self::hadamard(&h_low_prime, &h_high_prime);

            // Update `a` and `b` for the next round
            a = a_folded;
            b = b_folded;

            // Update the commitment key
            ck = Gens {
                G: g_prime,
                H: h_prime,
                u: ck.u,
            };

            n = n_prime;
            n_prime = n / 2;
        }

        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(L_vec.len(), num_rounds);
        assert_eq!(R_vec.len(), num_rounds);

        InnerProductProof {
            comm: comm_a.comm,
            L_vec,
            R_vec,
            b: b_vec,
            a: a[0],
            y,
        }
    }

    fn compute_scalars(
        r: &[ScalarField<C>],
        r_inv: &[ScalarField<C>],
        n: usize,
    ) -> Vec<ScalarField<C>> {
        let m = r.len();
        assert_eq!(2usize.pow(m as u32), n);

        let mut s = Vec::with_capacity(n);

        for i in 0..n {
            let mut s_i = ScalarField::<C>::ONE;
            for j in 0..m {
                if i >> j & 1 == 1 {
                    // s_i *= r[m - j - 1];
                    s_i *= r[j];
                } else {
                    // s_i *= r_inv[m - j - 1];
                    s_i *= r_inv[j];
                }
            }

            s.push(s_i);
        }

        s
    }

    pub fn verify(
        &self,
        proof: &InnerProductProof<C>,
        transcript: &mut Transcript<C>,
        compute_inters: bool,
    ) -> Option<IPAInters<C>> {
        let n = proof.b.len();

        // Get all the challenges from the transcript
        let r = proof
            .L_vec
            .iter()
            .zip(proof.R_vec.iter())
            .enumerate()
            .map(|(i, (L, R))| {
                transcript.append_point(*L);
                transcript.append_point(*R);
                transcript.challenge_fe(format!("r_{}", i))
            })
            .collect::<Vec<ScalarField<C>>>();

        let r_inv = r
            .iter()
            .map(|r| r.inverse().unwrap())
            .collect::<Vec<ScalarField<C>>>();

        let s = Self::compute_scalars(&r, &r_inv, n);

        // TODO: Can we avoid computing the inverse of s here?
        let s_inv = s
            .iter()
            .map(|s| s.inverse().unwrap())
            .collect::<Vec<ScalarField<C>>>();

        let s_a = Self::scale_vec(&s, proof.a);

        let mut b_folded = proof.b.clone();
        for (r_i, r_inv_i) in r.iter().zip(r_inv.iter()) {
            b_folded = Self::fold(&b_folded, *r_inv_i, *r_i);
        }

        // Sanity check
        assert_eq!(b_folded.len(), 1);

        let b = b_folded[0];

        let s_b = Self::scale_vec(&s_inv, b);

        //let s_b = Self::scale_vec(&s_inv, b);
        let a_b = proof.a * b;

        let inters = if compute_inters {
            let sa_G_inters = msm_powers(&s_a, &self.gens.G[..s_a.len()]);
            let sb_H_inters = msm_powers(&s_b, &self.gens.H[..s_b.len()]);
            let b_H_inters = msm_powers(&proof.b, &self.gens.H[..proof.b.len()]);

            Some(IPAInters {
                sa_G_inters,
                sb_H_inters,
                b_H_inters,
            })
        } else {
            None
        };

        let lhs = msm::<C>(&s_a, &self.gens.G[..s_a.len()])
            + msm::<C>(&s_b, &self.gens.H[..s_b.len()])
            + self.gens.u.unwrap() * a_b;

        // Compute P
        let mut rhs = proof.comm
            + msm(&proof.b, &self.gens.H[..proof.b.len()])
            + self.gens.u.unwrap() * proof.y;

        for (r_i, L_i) in r.iter().zip(proof.L_vec.iter()) {
            rhs += *L_i * (r_i.square());
        }

        for (r_inv_i, R_i) in r_inv.iter().zip(proof.R_vec.iter()) {
            rhs += *R_i * (r_inv_i.square());
        }

        assert_eq!(lhs.into_affine(), rhs.into_affine());

        inters
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        spartan::polynomial::eq_poly::EqPoly,
        spartan::polynomial::ml_poly::MlPoly,
        timer::{timer_end, timer_start},
    };

    use super::*;

    type F = ark_secq256k1::Fr;
    type Curve = ark_secq256k1::Projective;

    #[test]
    fn test_bulletproof() {
        let m = 5;
        let n = 2usize.pow(m as u32);
        let a = (0..n).map(|i| F::from(i as u64)).collect::<Vec<F>>();
        let poly = MlPoly::new(a.clone());
        let x = (0..m).map(|i| F::from(i as u64)).collect::<Vec<F>>();
        let y = poly.eval(&x);

        let b = EqPoly::new(x).evals();

        let bp = Bulletproof::<Curve>::new(n);
        let blinder = F::from(3);
        let comm_timer = timer_start("Commit");
        let comm = bp.commit(a, blinder);
        timer_end(comm_timer);

        let mut prover_transcript = Transcript::new(b"test");
        let open_timer = timer_start("Open");
        let eval_proof = bp.open(&comm, b.clone(), &mut prover_transcript);
        timer_end(open_timer);

        assert_eq!(eval_proof.y, y);

        let mut verifier_transcript = Transcript::new(b"test");
        bp.verify(&eval_proof, &mut verifier_transcript, false);
    }
}
