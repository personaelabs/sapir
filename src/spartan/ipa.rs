use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    spartan::utils::{inner_prod, msm_powers},
    timer::{profiler_end, profiler_start},
    ScalarField,
};

use super::{
    commitment::Gens,
    transcript::Transcript,
    utils::{msm, msm_affine},
};

#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct InnerProductProof<C: CurveGroup> {
    pub comm: C,
    pub b: Vec<ScalarField<C>>,
    pub y: ScalarField<C>,
    pub L_vec: Vec<C>,
    pub R_vec: Vec<C>,
    pub a: ScalarField<C>,
    pub r_prime: ScalarField<C>,
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
    pub blinder: ScalarField<C>,
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
                G_affine: vec![],
                G: vec![],
                H: None,
                u: None,
            },
        }
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
    pub fn commit(&self, a: Vec<ScalarField<C>>, blinder: ScalarField<C>) -> IPAComm<C> {
        let comm =
            msm_affine::<C>(&a, &self.gens.G_affine[..a.len()]) + self.gens.H.unwrap() * blinder;

        IPAComm {
            comm,
            poly: a,
            blinder,
        }
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
        assert!(n.is_power_of_two());

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

        let mut u_vec = Vec::with_capacity(num_rounds);
        let mut u_inv_vec = Vec::with_capacity(num_rounds);
        let mut r_vec = Vec::with_capacity(num_rounds);
        let mut l_vec = Vec::with_capacity(num_rounds);

        let mut rng = ark_std::rand::thread_rng();
        while n != 1 {
            let a_low = &a[..n_prime];
            let a_high = &a[n_prime..];

            let b_low = &b[..n_prime];
            let b_high = &b[n_prime..];

            let G_low = &ck.G[..n_prime];
            let G_high = &ck.G[n_prime..(n_prime * 2)];

            let r_i = ScalarField::<C>::rand(&mut rng);
            let l_i = ScalarField::<C>::rand(&mut rng);
            r_vec.push(r_i);
            l_vec.push(l_i);

            let L = msm(a_low, G_high)
                + ck.H.unwrap() * l_i
                + ck.u.unwrap() * inner_prod(a_low, b_high);
            let R = msm(a_high, G_low)
                + ck.H.unwrap() * r_i
                + ck.u.unwrap() * inner_prod(a_high, b_low);

            L_vec.push(L);
            R_vec.push(R);

            // Append L and R into the transcript
            transcript.append_point(L);
            transcript.append_point(R);

            // Get the challenge `r`
            let u = transcript.challenge_fe("r".to_string());
            let u_inv = u.inverse().unwrap();
            u_vec.push(u);
            u_inv_vec.push(u_inv);

            // Fold a and b
            let a_folded = Self::fold(&a, u, u_inv);
            let b_folded = Self::fold(&b, u_inv, u);

            // Update the basis
            let g_low_prime = Self::scale_points(&ck.G[..n_prime], u_inv);
            let g_high_prime = Self::scale_points(&ck.G[n_prime..(n_prime * 2)], u);
            let g_prime = Self::hadamard(&g_low_prime, &g_high_prime);

            // Update `a` and `b` for the next round
            a = a_folded;
            b = b_folded;

            // Update the commitment key
            ck = Gens {
                G_affine: vec![], // We don't use the affine form of the generators
                G: g_prime,
                H: ck.H,
                u: ck.u,
            };

            n = n_prime;
            n_prime = n / 2;
        }

        // ZK-open the final a and the blind factor
        let mut r_prime = ScalarField::<C>::ZERO;

        for (u_i, l_i) in u_vec.iter().zip(l_vec.iter()) {
            r_prime += *u_i * *u_i * *l_i;
        }

        for (u_inv_i, r_i) in u_inv_vec.iter().zip(r_vec.iter()) {
            r_prime += *u_inv_i * *u_inv_i * *r_i;
        }

        r_prime += comm_a.blinder;

        // Prove knowledge of a[0] and r_prime

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
            r_prime,
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
            let sb_H_inters = vec![];
            let b_H_inters = vec![];

            Some(IPAInters {
                sa_G_inters,
                sb_H_inters,
                b_H_inters,
            })
        } else {
            None
        };

        let lhs = msm::<C>(&s_a, &self.gens.G[..s_a.len()])
            + self.gens.H.unwrap() * proof.r_prime
            + self.gens.u.unwrap() * a_b;

        // Compute P
        let mut rhs = proof.comm + self.gens.u.unwrap() * proof.y;

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
