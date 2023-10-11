use crate::ScalarField;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Transcript<C: CurveGroup> {
    inner: merlin::Transcript,
    _marker: PhantomData<C>,
}

impl<C: CurveGroup> Transcript<C> {
    pub fn new(_label: &'static [u8]) -> Self {
        let inner = merlin::Transcript::new(_label);

        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn append_scalar(&mut self, s: ScalarField<C>) {
        self.inner
            .append_message(b"scalar", &s.into_bigint().to_bytes_be());
    }

    pub fn append_point(&mut self, p: C) {
        self.inner.append_message(b"p", &p.to_string().as_bytes());
    }

    pub fn append_points(&mut self, points: &[C]) {
        for p in points {
            self.append_point(*p);
        }
    }

    pub fn challenge_scalar(&mut self, label: &'static [u8]) -> ScalarField<C> {
        let mut bytes = [0u8; 32];
        self.inner.challenge_bytes(label, &mut bytes);

        ScalarField::<C>::from_random_bytes(&bytes).unwrap()
    }

    pub fn challenge_scalars(&mut self, n: usize, label: &'static [u8]) -> Vec<ScalarField<C>> {
        let mut c = Vec::with_capacity(n);
        for _ in 0..n {
            let c_i = self.challenge_scalar(label);
            c.push(c_i);
        }

        c
    }
}
