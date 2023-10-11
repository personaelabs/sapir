use crate::{
    spartan::utils::{inner_prod, msm_powers},
    ScalarField,
};
use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::{
    commitment::Gens,
    transcript::Transcript,
    utils::{msm, msm_affine},
};

#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct InnerProductProof<C: CurveGroup> {
    pub comm: C,
    pub y: ScalarField<C>,
    pub L_vec: Vec<C>,
    pub R_vec: Vec<C>,
    pub R: C,
    pub z1: ScalarField<C>,
    pub z2: ScalarField<C>,
}

#[derive(Clone)]
pub struct IPAInters<C: CurveGroup> {
    pub s_G_inters: Vec<C>,
}

pub struct IPAComm<C: CurveGroup> {
    pub comm: C,
    // Evaluations of the polynomial
    pub poly: Vec<ScalarField<C>>,
    pub blinder: ScalarField<C>,
}

// We implement the Polynomial commitment scheme described in
// section 3 of the halo paper: https://eprint.iacr.org/2019/1021.pdf
#[derive(Clone)]
pub struct IPA<C: CurveGroup> {
    pub gens: Gens<C>,
}

impl<C: CurveGroup> IPA<C> {
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

    // Hadamard product of elliptic curve points
    fn hadamard(a: &[C], b: &[C]) -> Vec<C> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(a, b)| *a + *b).collect()
    }

    // Return the Pedersen commitment to a vector with the given blinder
    pub fn commit(&self, a: Vec<ScalarField<C>>, blinder: ScalarField<C>) -> IPAComm<C> {
        let comm =
            msm_affine::<C>(&a, &self.gens.G_affine[..a.len()]) + self.gens.H.unwrap() * blinder;

        IPAComm {
            comm,
            poly: a,
            blinder,
        }
    }

    // Open the inner product <a, b> = y in zero-knowledge
    // Implements the "Modified inner product" from https://eprint.iacr.org/2019/1021.pdf
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
        let y = inner_prod(&a, &b);

        let mut a = a;
        let mut b = b;
        let mut ck = self.gens.clone();

        // Add the the claimed evaluation to the transcript
        transcript.append_scalar(y);

        // Get a challenge to rescale the basis
        let x = transcript.challenge_scalar(b"x");

        // Rescale `u`
        ck.u = Some(ck.u.unwrap() * x);

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

            // Append L and R to the transcript
            transcript.append_point(L);
            transcript.append_point(R);

            let u = transcript.challenge_scalar(b"r");
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

        // Compute `r_prime``
        let mut r_prime = ScalarField::<C>::ZERO;

        for (u_i, l_i) in u_vec.iter().zip(l_vec.iter()) {
            r_prime += *u_i * *u_i * *l_i;
        }

        for (u_inv_i, r_i) in u_inv_vec.iter().zip(r_vec.iter()) {
            r_prime += *u_inv_i * *u_inv_i * *r_i;
        }

        r_prime += comm_a.blinder;

        // Prove knowledge of a[0] and r_prime in zero-knowledge
        // "Zero-Knowledge Opening" from https://eprint.iacr.org/2019/1021.pdf

        let d = ScalarField::<C>::rand(&mut rng);
        let s = ScalarField::<C>::rand(&mut rng);

        // Sanity checks
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(L_vec.len(), num_rounds);
        assert_eq!(R_vec.len(), num_rounds);

        let G_final = ck.G[0];
        let b_final = b[0];
        let a_final = a[0];
        let R = (G_final + (ck.u.unwrap() * b_final).into_affine()) * d + (ck.H.unwrap() * s);

        transcript.append_point(R);
        let c = transcript.challenge_scalar(b"c");

        let z1 = d + (c * a_final);
        let z2 = s + (c * r_prime);

        InnerProductProof {
            comm: comm_a.comm,
            L_vec,
            R_vec,
            y,
            R,
            z1,
            z2,
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
                    s_i *= r[m - j - 1];
                } else {
                    s_i *= r_inv[m - j - 1];
                }
            }

            s.push(s_i);
        }

        s
    }

    pub fn verify(
        &self,
        proof: &InnerProductProof<C>,
        b: Vec<ScalarField<C>>,
        transcript: &mut Transcript<C>,
        compute_inters: bool,
    ) -> Option<IPAInters<C>> {
        let n = b.len();

        // Append the claimed evaluation to the transcript
        transcript.append_scalar(proof.y);

        // Rescale `u`
        let x = transcript.challenge_scalar(b"x");
        let u = self.gens.u.unwrap() * x;

        // Get all the challenges from the transcript
        let r = proof
            .L_vec
            .iter()
            .zip(proof.R_vec.iter())
            .map(|(L, R)| {
                transcript.append_point(*L);
                transcript.append_point(*R);
                transcript.challenge_scalar(b"r")
            })
            .collect::<Vec<ScalarField<C>>>();

        let r_inv = r
            .iter()
            .map(|r| r.inverse().unwrap())
            .collect::<Vec<ScalarField<C>>>();

        let s = Self::compute_scalars(&r, &r_inv, n);

        let mut b_folded = b.clone();
        for (r_i, r_inv_i) in r.iter().zip(r_inv.iter()) {
            b_folded = Self::fold(&b_folded, *r_inv_i, *r_i);
        }

        // Sanity check
        assert_eq!(b_folded.len(), 1);

        let b = b_folded[0];

        // Compute the intermediate values used for optimistic verification
        let inters = if compute_inters {
            let s_G_inters = msm_powers(&s, &self.gens.G[..s.len()]);

            Some(IPAInters { s_G_inters })
        } else {
            None
        };

        let G_final = msm_affine::<C>(&s, &self.gens.G_affine[..s.len()]).into_affine();

        // Compute Q
        let mut Q = proof.comm + u * proof.y;

        for (r_i, L_i) in r.iter().zip(proof.L_vec.iter()) {
            Q += *L_i * (r_i.square());
        }

        for (r_inv_i, R_i) in r_inv.iter().zip(proof.R_vec.iter()) {
            Q += *R_i * (r_inv_i.square());
        }

        // Verify the zero-knowledge opening

        transcript.append_point(proof.R);
        let c = transcript.challenge_scalar(b"c");

        let lhs = (Q * c).into_affine() + proof.R;
        let rhs = (G_final + (u * b).into_affine()) * proof.z1 + self.gens.H.unwrap() * proof.z2;

        assert_eq!(lhs.into_affine(), rhs.into_affine());

        inters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        spartan::polynomial::eq_poly::EqPoly,
        spartan::polynomial::ml_poly::MlPoly,
        timer::{timer_end, timer_start},
    };

    type F = ark_secq256k1::Fr;
    type Curve = ark_secq256k1::Projective;

    #[test]
    fn test_ipa() {
        let m = 5;
        let n = 2usize.pow(m as u32);
        let a = (0..n).map(|i| F::from(i as u64)).collect::<Vec<F>>();
        let poly = MlPoly::new(a.clone());
        let x = (0..m).map(|i| F::from(i as u64)).collect::<Vec<F>>();
        let y = poly.eval(&x);

        let b = EqPoly::new(x).evals();

        let ipa = IPA::<Curve>::new(n);
        let blinder = F::from(3);
        let comm_timer = timer_start("Commit");
        let comm = ipa.commit(a, blinder);
        timer_end(comm_timer);

        let mut prover_transcript = Transcript::new(b"test");
        let open_timer = timer_start("Open");
        let eval_proof = ipa.open(&comm, b.clone(), &mut prover_transcript);
        timer_end(open_timer);

        assert_eq!(eval_proof.y, y);

        let mut verifier_transcript = Transcript::new(b"test");
        ipa.verify(&eval_proof, b, &mut verifier_transcript, false);
    }
}
