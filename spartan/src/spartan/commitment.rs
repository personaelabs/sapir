use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use sha3::{
    digest::{ExtendableOutput, Input, XofReader},
    Shake256,
};

#[derive(Clone)]
pub struct Gens<C: CurveGroup> {
    pub G: Vec<C>,
    pub H: Vec<C>,
    pub u: Option<C>,
}

impl<C: CurveGroup> Gens<C> {
    pub fn new(n: usize) -> Self {
        // Inspired by microsoft/Spartan
        let mut shake = Shake256::default();
        shake.input(b"spartan-evm");

        let mut reader = shake.xof_result();
        let mut uniform_bytes = [0u8; 32];

        // TODO: Produce the same uniformly random points for every call
        let mut rng = ark_std::rand::thread_rng();
        let mut G: Vec<C> = Vec::new();
        for _ in 0..n {
            reader.read(&mut uniform_bytes);
            G.push(C::Affine::rand(&mut rng).into());
        }

        let mut H: Vec<C> = Vec::new();
        for _ in 0..n {
            reader.read(&mut uniform_bytes);
            H.push(C::Affine::rand(&mut rng).into());
        }

        reader.read(&mut uniform_bytes);
        let u = C::Affine::rand(&mut rng).into();

        // TODO: This is not secure
        Self { G, H, u: Some(u) }
    }
}
