use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct UniPoly<F: PrimeField> {
    pub coeffs: Vec<F>, // coefficients in ascending degree
    pub eval_at_1: F,
}

impl<F: PrimeField> UniPoly<F> {
    pub fn new(coeffs: Vec<F>) -> Self {
        let eval_at_1 = coeffs.iter().fold(F::ZERO, |acc, f| acc + f);
        Self { coeffs, eval_at_1 }
    }

    fn eval_cubic(&self, x: F) -> F {
        // ax^3 + bx^2 + cx + d
        let x_sq = x.square();
        let x_cub = x_sq * x;

        let a = self.coeffs[0];
        let b = self.coeffs[1];
        let c = self.coeffs[2];
        let d = self.coeffs[3];

        a * x_cub + b * x_sq + c * x + d
    }

    fn eval_quadratic(&self, x: F) -> F {
        // ax^3 + bx^2 + cx + d
        let x_sq = x.square();

        let a = self.coeffs[0];
        let b = self.coeffs[1];
        let c = self.coeffs[2];

        a * x_sq + b * x + c
    }

    pub fn eval(&self, x: F) -> F {
        if self.coeffs.len() == 3 {
            self.eval_quadratic(x)
        } else {
            self.eval_cubic(x)
        }
    }

    pub fn eval_binary(&self, x: bool) -> F {
        if x {
            self.eval_at_1
        } else {
            self.coeffs[self.coeffs.len() - 1]
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
            let eval_at_1 = coeffs.iter().fold(F::ZERO, |acc, f| acc + f);
            Self { coeffs, eval_at_1 }
        } else {
            let c = evals[0];
            let a = (evals[2] - evals[1] - evals[1] + evals[0]) * two_inv;
            let b = evals[1] - a - c;

            let coeffs = vec![a, b, c];
            let eval_at_1 = coeffs.iter().fold(F::ZERO, |acc, f| acc + f);
            Self { coeffs, eval_at_1 }
        }
    }
}
