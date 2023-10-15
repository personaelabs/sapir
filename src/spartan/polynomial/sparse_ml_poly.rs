use super::eq_poly::EqPoly;
use ark_ff::PrimeField;
#[cfg(feature = "parallel")]
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

#[derive(Clone, Debug)]
pub struct SparseMLPoly<F> {
    pub evals: Vec<(u64, F)>,
    pub num_vars: usize,
}

impl<F: PrimeField> SparseMLPoly<F> {
    pub fn new(evals: Vec<(u64, F)>, num_vars: usize) -> Self {
        Self { evals, num_vars }
    }

    pub fn num_entries(&self) -> usize {
        2usize.pow(self.num_vars as u32)
    }

    // `x` should be in big-endian form when treated as bits
    pub fn eval(&self, x: &[F]) -> F {
        debug_assert_eq!(self.num_vars, x.len());

        let eq_poly = EqPoly::new(x.to_vec());
        let eq_evals = eq_poly.evals();

        let mut result = F::ZERO;

        for eval in &self.evals {
            result += eq_evals[eval.0 as usize] * eval.1;
        }

        result
    }

    pub fn eval_naive(&self, t: &[F]) -> F {
        debug_assert_eq!(self.num_vars, t.len());

        let eq_poly = EqPoly::new(t.to_vec());

        #[cfg(feature = "parallel")]
        let result = self
            .evals
            .par_iter()
            .map(|eval| eq_poly.eval_as_bits(eval.0) * eval.1)
            .sum();

        #[cfg(not(feature = "parallel"))]
        let result = self
            .evals
            .iter()
            .map(|eval| eq_poly.eval_as_bits(eval.0) * eval.1)
            .sum();

        result
    }
}
