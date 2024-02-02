use crate::ScalarField;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_ff::{BigInteger, Field};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Transcript<C: CurveGroup> {
    inner: merlin::Transcript,
    _marker: PhantomData<C>,
}

impl<C: CurveGroup> Transcript<C> {
    pub fn new(label: &'static [u8]) -> Self {
        let inner = merlin::Transcript::new(label);

        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn append_scalar(&mut self, label: &'static [u8], s: ScalarField<C>) {
        self.inner
            .append_message(label, &s.into_bigint().to_bytes_be());
    }

    pub fn append_point(&mut self, label: &'static [u8], p: C) {
        self.inner.append_message(label, &p.to_string().as_bytes());
    }

    pub fn append_points(&mut self, label: &'static [u8], points: &[C]) {
        for p in points {
            self.append_point(label, *p);
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
