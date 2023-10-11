use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone)]
pub struct Gens<C: CurveGroup> {
    pub G: Vec<C>,
    pub G_affine: Vec<C::Affine>,
    pub H: Option<C>,
    pub u: Option<C>,
}

impl<C: CurveGroup> Gens<C> {
    pub fn new(n: usize) -> Self {
        let seed = [33u8; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut G: Vec<C> = Vec::new();
        let mut G_affine: Vec<C::Affine> = Vec::new();

        for _ in 0..n {
            let G_i = C::Affine::rand(&mut rng);
            G_affine.push(G_i);
            G.push(G_i.into());
        }

        let H: C = C::Affine::rand(&mut rng).into();
        let u = C::Affine::rand(&mut rng).into();

        Self {
            G,
            G_affine,
            H: Some(H),
            u: Some(u),
        }
    }
}
