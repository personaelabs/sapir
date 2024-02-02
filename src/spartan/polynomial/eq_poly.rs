use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct EqPoly<F: Field> {
    t: Vec<F>,
    one_minus_t: Vec<F>,
}

impl<F: Field> EqPoly<F> {
    pub fn new(t: Vec<F>) -> Self {
        let mut one_minus_t = vec![];
        for t_i in &t {
            one_minus_t.push(F::ONE - t_i);
        }
        Self { t, one_minus_t }
    }

    // `x` should be in big-endian when treated as bits
    pub fn eval(&self, x: &[F]) -> F {
        let mut result = F::ONE;
        let one = F::ONE;

        for i in 0..x.len() {
            result *= self.t[i] * x[i] + (one - self.t[i]) * (one - x[i]);
        }
        result
    }

    pub fn eval_as_bits_inters(&self, x: u64) -> (F, Vec<F>) {
        let mut result = F::ONE;

        let m = self.t.len();
        let mut inters = vec![];
        for i in (0..m).rev() {
            let bit = (x >> i) & 1;
            result *= if bit == 1 {
                self.t[m - i - 1]
            } else {
                self.one_minus_t[m - i - 1]
            };
            inters.push(result);
        }

        (result, inters)
    }

    pub fn eval_as_bits(&self, x: u64) -> F {
        let mut result = F::ONE;

        let m = self.t.len();
        for i in (0..m).rev() {
            let bit = (x >> i) & 1;
            result *= if bit == 1 {
                self.t[m - i - 1]
            } else {
                self.one_minus_t[m - i - 1]
            };
        }

        result
    }

    // Evaluate the polynomial at `x` as bits
    pub fn eval_as_bits_with_inters(&self, x: u64, x_prev: u64, inters: &mut Vec<F>) -> F {
        let m = self.t.len();
        let mut dup_bits = 0;
        for i in (0..m).rev() {
            let x_i = (x >> i) & 1;
            let x_prev_i = (x_prev >> i) & 1;
            if x_i == x_prev_i {
                dup_bits += 1;
            } else {
                break;
            }
        }

        // We can use the previous result up until `dup_bits`
        let mut result = if dup_bits == 0 {
            F::ONE
        } else {
            inters[dup_bits - 1]
        };

        for i in (0..(m - dup_bits)).rev() {
            let bit = (x >> i) & 1;
            result *= if bit == 1 {
                self.t[m - i - 1]
            } else {
                self.one_minus_t[m - i - 1]
            };
            inters[m - i - 1] = result;
        }
        result
    }

    // Copied from microsoft/Spartan
    // Return the evaluations over the boolean hypercube
    pub fn evals(&self) -> Vec<F> {
        let ell = self.t.len();

        let mut evals: Vec<F> = vec![F::ONE; 2usize.pow(ell as u32)];
        let mut size = 1;
        for j in 0..ell {
            // in each iteration, we double the size of chis
            size *= 2;
            for i in (0..size).rev().step_by(2) {
                // copy each element from the prior iteration twice
                let scalar = evals[i / 2];
                evals[i] = scalar * self.t[j];
                evals[i - 1] = scalar - evals[i];
            }
        }
        evals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type F = ark_secq256k1::Fq;

    #[test]
    fn test_eq_poly() {
        let ZERO = F::from(0u32);
        let ONE = F::from(1u32);

        let m = 4;
        let t = (0..m).map(|i| F::from((i + 33) as u64)).collect::<Vec<F>>();
        let eq_poly = EqPoly::new(t.clone());
        let evals = eq_poly.evals();

        let eval_first = eq_poly.eval(&[ZERO, ZERO, ZERO, ZERO]);
        assert_eq!(eval_first, evals[0], "The first evaluation is not correct");

        let eval_second = eq_poly.eval(&[ZERO, ZERO, ZERO, ONE]);
        assert_eq!(
            eval_second, evals[1],
            "The second evaluation is not correct"
        );

        let eval_last = eq_poly.eval(&[ONE, ONE, ONE, ONE]);
        assert_eq!(
            eval_last,
            evals[evals.len() - 1],
            "The last evaluation is not correct"
        );
    }

    #[test]
    fn test_eval_as_bits() {
        let m = 7;
        let t = (0..m).map(|i| F::from((i + 33) as u64)).collect::<Vec<_>>();
        let eq_poly = EqPoly::<F>::new(t);

        let xs = [1, 2, 3, 9, 10, 0, 13, 126];

        let (_, mut inters) = eq_poly.eval_as_bits_inters(xs[0]);
        let mut x_prev = xs[0];
        for x in xs.iter().skip(1) {
            let eval = eq_poly.eval_as_bits_with_inters(*x, x_prev, &mut inters);

            assert_eq!(eval, eq_poly.eval_as_bits(*x));
            x_prev = *x;
        }
    }
}
