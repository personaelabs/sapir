use crate::frontend::constraint_system::{ConstraintSystem, Wire};
use crate::frontend::gadgets::poseidon::sponge::PoseidonSpongeChip;
use ark_ff::PrimeField;

const ARTY: usize = 2;
const SPONGE_WIDTH: usize = ARTY + 1; // The sponge capacity is one, so the width is arity + 1

pub fn verify_merkle_proof<F: PrimeField>(
    leaf: Wire<F>,
    siblings: &[Wire<F>],
    path_indices: &[Wire<F>],
    poseidon_sponge: PoseidonSpongeChip<F, SPONGE_WIDTH>,
    cs: &mut ConstraintSystem<F>,
) -> Wire<F> {
    let mut poseidon_sponge = poseidon_sponge;
    let mut node = leaf;
    for (sibling, path) in siblings.iter().zip(path_indices.iter()) {
        poseidon_sponge.absorb(&[node, *sibling]);
        let left = poseidon_sponge.squeeze(1)[0];
        poseidon_sponge.absorb(&[*sibling, node]);
        let right = poseidon_sponge.squeeze(1)[0];
        node = cs.if_then(path.is_zero(), left).else_then(right);
    }

    node
}

/*
pub struct MerkleProof<F: PrimeField> {
    pub root: F,
    pub leaf: F,
    pub siblings: Vec<F>,
    pub path_indices: Vec<usize>,
}

pub struct MerkleTree<F: PrimeField> {
    pub root: F,
    pub proofs: BTreeMap<F, Vec<MerkleProof<F>>>,
}

impl<F: PrimeField> MerkleTree<F> {
    pub fn new(leaves: Vec<F>) -> Self {
        Self {
            root: F::ZERO,
            proofs: BTreeMap::new(),
        }
    }

    fn next_power_of(n: usize) -> (usize, usize) {
        let mut pow_of_n = 1;
        let mut pow = 0;
        while pow_of_n <= n {
            pow_of_n *= 3;
            pow += 1;
        }
        (pow_of_n, pow)
    }

    fn get_proofs(leaves: Vec<F>) -> (F, Vec<MerkleProof<F>>) {
        let (padded_leaves, num_layers) = Self::next_power_of(leaves.len());
        let mut layers = vec![leaves.clone()];

        let mut current_layer = leaves;
        let mut next_layer = Vec::with_capacity(current_layer.len() / ARTY);

        let mut poseidon_sponge = PoseidonSponge::new(
            SPONGE_WIDTH.to_string().as_bytes(),
            PoseidonCurve::SECP256K1,
            IOPattern::new(vec![SpongeOp::Absorb(ARTY), SpongeOp::Squeeze(1)]),
        );

        // Compute the layers and the root
        while current_layer.len() > 1 {
            for siblings in current_layer.into_iter().chunks(ARTY) {
                poseidon_sponge.absorb(&siblings);
                let parent = poseidon_sponge.squeeze(1)[0];
                next_layer.push(parent);
            }

            current_layer = next_layer.clone();
            layers.push(next_layer);
            next_layer = Vec::with_capacity(current_layer.len() / ARTY);
        }

        let root = current_layer[0];

        let proofs = vec![];

        for i in 0..leaves.len() {
            let leaf = leaves[i];
            let mut siblings = vec![];

            // Store the index of the node.
            let path_indices = (0..num_layers).map(|l_i| i / l_i).collect::<Vec<usize>>();
            let siblings = layers.iter().map(|layer| layer);

            let mut current_layer = leaf;

            for layer in layers.iter().rev() {
                let mut sibling = None;
                let mut path_index = None;

                for (i, node) in layer.iter().enumerate() {
                    if *node == current_layer {
                        if i % ARTY == 0 {
                            sibling = Some(layer[i + 1]);
                            path_index = Some(0);
                        } else {
                            sibling = Some(layer[i - 1]);
                            path_index = Some(1);
                        }
                    }
                }

                siblings.push(sibling.unwrap());
                path_indices.push(path_index.unwrap());
                current_layer = layer[0];
            }

            proofs.push(MerkleProof {
                root,
                leaf,
                siblings,
                path_indices,
            });
        }

        (root, proofs)
    }
}
 */

#[cfg(test)]
mod tests {
    use poseidon::{
        constants::secp256k1_w3,
        sponge::{IOPattern, PoseidonSponge, SpongeOp},
    };

    use super::*;

    type F = ark_secp256k1::Fq;
    const TREE_DEPTH: usize = 5;

    #[test]
    pub fn test_verify_merkle_proof() {
        let constants = secp256k1_w3();
        let mut poseidon_sponge = PoseidonSponge::<F, SPONGE_WIDTH>::new(
            constants.clone(),
            SPONGE_WIDTH.to_string().as_bytes(),
            IOPattern::new(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]),
        );

        let synthesizer = |cs: &mut ConstraintSystem<F>| {
            let leaf = cs.alloc_priv_input();
            let siblings = cs.alloc_priv_inputs(TREE_DEPTH);
            let path_indices = cs.alloc_priv_inputs(TREE_DEPTH);

            let sponge_chip = PoseidonSpongeChip::<F, SPONGE_WIDTH>::new(
                SPONGE_WIDTH.to_string().as_bytes(),
                IOPattern::new(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]),
                constants.clone(),
                cs,
            );

            let node = verify_merkle_proof(leaf, &siblings, &path_indices, sponge_chip.clone(), cs);
            cs.expose_public(node);
        };

        let siblings = (0..TREE_DEPTH)
            .map(|i| F::from(i as u64))
            .collect::<Vec<F>>();

        let path_indices = (0..TREE_DEPTH).map(|i| i % 3).collect::<Vec<usize>>();

        // Compute the expected root

        let leaf = F::from(3u32);
        let mut node = leaf;
        for (sibling, sel) in siblings.iter().zip(path_indices.iter()) {
            if sel & 1 == 1 {
                poseidon_sponge.absorb(&[node, *sibling]);
                node = poseidon_sponge.squeeze(1)[0];
            } else {
                poseidon_sponge.absorb(&[*sibling, node]);
                node = poseidon_sponge.squeeze(1)[0];
            }
        }

        let expected_root = node;

        // Run the circuit

        let mut cs = ConstraintSystem::new();
        let mut priv_input = vec![];
        priv_input.push(leaf);
        priv_input.extend_from_slice(&siblings);
        priv_input.extend_from_slice(
            &path_indices
                .iter()
                .map(|x| F::from(*x as u64))
                .collect::<Vec<F>>(),
        );

        let pub_input = [expected_root];
        let witness = cs.gen_witness(synthesizer, &pub_input, &priv_input);

        cs.set_constraints(&synthesizer);
        assert!(cs.is_sat(&witness, &pub_input));
    }
}
