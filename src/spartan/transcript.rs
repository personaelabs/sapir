use ark_ec::{CurveConfig, CurveGroup};
use std::collections::BTreeMap;
use std::marker::PhantomData;

use crate::ScalarField;

#[derive(Clone)]
pub struct Transcript<C: CurveGroup> {
    _marker: PhantomData<C>,
    challenges: BTreeMap<String, ScalarField<C>>, // We store challenges for later reference
}

impl<C: CurveGroup> Transcript<C> {
    pub fn new(_label: &'static [u8]) -> Self {
        // TODO: Append label to transcript
        Self {
            _marker: PhantomData,
            challenges: BTreeMap::new(),
        }
    }

    pub fn append_fe(&mut self, _fe: ScalarField<C>) {
        // TBD
    }

    pub fn append_point(&mut self, _p: C) {
        // TBD
    }

    pub fn append_points(&mut self, _points: &[C]) {}

    pub fn append_bytes(&mut self, _bytes: &[u8]) {}

    pub fn challenge_vec(
        &mut self,
        n: usize,
        label: String,
    ) -> Vec<<C::Config as CurveConfig>::ScalarField> {
        //! This is temporary
        let c = (0..n)
            .map(|_| ScalarField::<C>::from(33u32))
            .collect::<Vec<ScalarField<C>>>();

        for i in 0..n {
            let label_i = format!("{}-{}", label, i);
            if self.challenges.contains_key(label_i.as_str()) {
                panic!("Challenge label {} already exists", label_i);
            }
            self.challenges.insert(label_i, c[i]);
        }

        c
    }

    pub fn challenge_fe(&mut self, _label: String) -> ScalarField<C> {
        // TBD

        //! This is temporary
        ScalarField::<C>::from(33u32)
    }

    pub fn get(&self, label: &str) -> ScalarField<C> {
        *self
            .challenges
            .get(label)
            .unwrap_or_else(|| panic!("Challenge label {} does not exist", label))
    }
}
