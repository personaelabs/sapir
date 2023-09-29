use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::PrimeField;

pub fn inner_prod<F: PrimeField>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len());
    let mut result = F::ZERO;
    for i in 0..a.len() {
        result += a[i] * b[i];
    }
    result
}

pub fn msm_powers<C: CurveGroup>(
    scalars: &[<C::Config as CurveConfig>::ScalarField],
    points: &[C],
) -> Vec<C> {
    let mut powers = Vec::with_capacity(scalars.len());

    for (scalar, p) in scalars.iter().zip(points.iter()) {
        powers.push(*p * *scalar);
    }

    powers
}

pub fn msm<C: CurveGroup>(scalars: &[<C::Config as CurveConfig>::ScalarField], points: &[C]) -> C {
    assert_eq!(scalars.len(), points.len());

    // TODO: Can we avoid converting to affine?
    let affine_points = points
        .iter()
        .map(|p| p.into_affine())
        .collect::<Vec<C::Affine>>();
    C::msm_unchecked(&affine_points, scalars)
}
