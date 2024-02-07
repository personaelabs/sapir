use crate::ScalarField;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::Field;
use ark_ff::Zero;

pub fn inner_prod<F: Field>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len());
    let mut result = F::ZERO;
    for i in 0..a.len() {
        result += a[i] * b[i];
    }
    result
}

// MSM with affine points. This is faster than the version with projective points if
// the points are already affine.
pub fn msm_affine<C: CurveGroup>(scalars: &[ScalarField<C>], points: &[C::Affine]) -> C {
    assert_eq!(scalars.len(), points.len());

    let mut nonzero_scalar = Vec::with_capacity(scalars.len());
    let mut bases = Vec::with_capacity(points.len());

    // Filter out zero scalars and corresponding points
    for (s, p) in scalars.iter().zip(points.iter()) {
        if !s.is_zero() {
            nonzero_scalar.push(*s);
            bases.push(*p);
        }
    }

    C::msm_unchecked(&bases, &nonzero_scalar)
}

// MSM with projective points.
pub fn msm<C: CurveGroup>(scalars: &[<C::Config as CurveConfig>::ScalarField], points: &[C]) -> C {
    assert_eq!(scalars.len(), points.len());

    let mut nonzero_scalar = Vec::with_capacity(scalars.len());
    let mut bases = Vec::with_capacity(points.len());

    // Filter out zero scalars and corresponding points
    for (s, p) in scalars.iter().zip(points.iter()) {
        if !s.is_zero() {
            nonzero_scalar.push(*s);
            bases.push(p.into_affine());
        }
    }

    C::msm_unchecked(&bases, &nonzero_scalar)
}
