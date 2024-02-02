use core::panic;

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct UniPoly<F: Field> {
    pub coeffs: Vec<F>, // coefficients in ascending degree
    pub eval_at_0: F,
    pub eval_at_1: F,
    pub eval_at_2: F,
    pub eval_at_3: F,
}

impl<F: Field> UniPoly<F> {
    pub fn new(coeffs: Vec<F>) -> Self {
        let eval_at_0 = coeffs[coeffs.len() - 1];
        let eval_at_1 = coeffs.iter().fold(F::ZERO, |acc, f| acc + f);
        let eval_at_2 = Self::eval_static(&coeffs, F::from(2u64));
        let eval_at_3 = Self::eval_static(&coeffs, F::from(3u64));
        Self {
            coeffs,
            eval_at_0,
            eval_at_1,
            eval_at_2,
            eval_at_3,
        }
    }

    pub fn eval(&self, x: F) -> F {
        Self::eval_static(&self.coeffs, x)
    }

    pub fn eval_small(&self, x: usize) -> F {
        if x == 0 {
            self.eval_at_0
        } else if x == 1 {
            self.eval_at_1
        } else if x == 2 {
            self.eval_at_2
        } else if x == 3 {
            self.eval_at_3
        } else {
            panic!("x must be 0, 1, 2, or 3")
        }
    }

    pub fn eval_static(coeffs: &[F], x: F) -> F {
        let mut result = F::ZERO;
        let mut x_pow = F::ONE;
        for coeff in coeffs.iter().rev() {
            result += *coeff * x_pow;
            x_pow *= x;
        }
        result
    }

    pub fn eval_binary(&self, x: bool) -> F {
        if x {
            self.eval_at_1
        } else {
            self.eval_at_0
        }
    }

    pub fn interpolate(evals: &[F]) -> Self {
        debug_assert!(
            evals.len() == 4 || evals.len() == 3,
            "Only cubic and quadratic polynomials are supported"
        );

        let two_inv = F::from(2u64).inverse().unwrap();

        if evals.len() == 4 {
            // ax^3 + bx^2 + cx + d
            let six_inv = F::from(6u64).inverse().unwrap();

            let d = evals[0];
            let a = six_inv
                * (evals[3] - evals[2] - evals[2] - evals[2] + evals[1] + evals[1] + evals[1]
                    - evals[0]);
            let b = two_inv
                * (evals[0] + evals[0] - evals[1] - evals[1] - evals[1] - evals[1] - evals[1]
                    + evals[2]
                    + evals[2]
                    + evals[2]
                    + evals[2]
                    - evals[3]);

            let c = evals[1] - d - a - b;

            let coeffs = vec![a, b, c, d];
            let eval_at_0 = coeffs[coeffs.len() - 1];
            let eval_at_1 = Self::eval_static(&coeffs, F::from(1u64));
            let eval_at_2 = Self::eval_static(&coeffs, F::from(2u64));
            let eval_at_3 = Self::eval_static(&coeffs, F::from(3u64));
            Self {
                coeffs,
                eval_at_0,
                eval_at_1,
                eval_at_2,
                eval_at_3,
            }
        } else {
            let c = evals[0];
            let a = (evals[2] - evals[1] - evals[1] + evals[0]) * two_inv;
            let b = evals[1] - a - c;

            let coeffs = vec![a, b, c];

            let eval_at_0 = coeffs[coeffs.len() - 1];
            let eval_at_1 = Self::eval_static(&coeffs, F::from(1u64));
            let eval_at_2 = Self::eval_static(&coeffs, F::from(2u64));
            let eval_at_3 = Self::eval_static(&coeffs, F::from(3u64));

            Self {
                coeffs,
                eval_at_0,
                eval_at_1,
                eval_at_2,
                eval_at_3,
            }
        }
    }
}
