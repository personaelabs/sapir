use super::eq_poly::EqPoly;
use ark_ff::PrimeField;

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

        let (eval_first, mut inters) = eq_poly.eval_as_bits_inters(self.evals[0].0);

        let mut x_prev = self.evals[0].0;
        let mut result = eval_first * self.evals[0].1;

        for term in self.evals.iter().skip(1) {
            let x = term.0;
            let eval = eq_poly.eval_as_bits_with_inters(x, x_prev, &mut inters);
            result += eval * term.1;
            x_prev = x;
        }

        result
    }
}
