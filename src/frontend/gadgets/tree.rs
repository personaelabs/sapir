use crate::frontend::constraint_system::{ConstraintSystem, Wire};
use ark_ff::PrimeField;

use super::poseidon::poseidon::PoseidonChip;

const ARTY: usize = 2;
const SPONGE_WIDTH: usize = ARTY + 1; // The sponge capacity is one, so the width is arity + 1

fn hash<F: PrimeField>(
    left: Wire<F>,
    right: Wire<F>,
    poseidon: PoseidonChip<F, SPONGE_WIDTH>,
) -> Wire<F> {
    let cs = left.cs();
    let mut poseidon = poseidon;
    poseidon.state[0] = cs.alloc_const(F::from(3u32));
    poseidon.state[1] = left;
    poseidon.state[2] = right;

    poseidon.permute();
    poseidon.state[1]
}

pub fn verify_merkle_proof<F: PrimeField>(
    leaf: Wire<F>,
    siblings: &[Wire<F>],
    path_indices: &[Wire<F>],
    poseidon: PoseidonChip<F, SPONGE_WIDTH>,
    cs: &mut ConstraintSystem<F>,
) -> Wire<F> {
    let mut node = leaf;
    for (sibling, path) in siblings.iter().zip(path_indices.iter()) {
        let left = hash(node, *sibling, poseidon.clone());
        let right = hash(*sibling, node, poseidon.clone());

        node = cs.if_then(path.is_zero(), left).else_then(right);
    }

    node
}

#[cfg(test)]
mod tests {
    use merkle_tree::MerkleTree;
    use poseidon::constants::secp256k1_w3;

    use crate::test_var_pub_input;

    use super::*;

    type F = ark_secp256k1::Fq;
    const TREE_DEPTH: usize = 5;

    #[test]
    pub fn test_verify_merkle_proof() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let leaf = cs.alloc_priv_input();
            let siblings = cs.alloc_priv_inputs(TREE_DEPTH);
            let path_indices = cs.alloc_priv_inputs(TREE_DEPTH);

            let poseidon_chip = PoseidonChip::<F, SPONGE_WIDTH>::new(cs, secp256k1_w3());

            let root =
                verify_merkle_proof(leaf, &siblings, &path_indices, poseidon_chip.clone(), cs);

            cs.expose_public(root);
        };

        // Construct a mock tree
        let num_leave = 1 << TREE_DEPTH;
        let mut tree = MerkleTree::<F, SPONGE_WIDTH>::new(secp256k1_w3());
        let leaves = (0..num_leave)
            .map(|i| F::from(i as u32))
            .collect::<Vec<F>>();

        // Run the circuit
        for leaf in &leaves {
            tree.insert(*leaf);
        }

        tree.finish();
        let expected_root = tree.root.unwrap();

        // Create a merkle proof
        let leaf = leaves[3];
        let merkle_proof = tree.create_proof(leaf);

        let mut priv_input = vec![];
        priv_input.push(leaf);
        priv_input.extend_from_slice(&merkle_proof.siblings);
        priv_input.extend_from_slice(
            &merkle_proof
                .path_indices
                .iter()
                .map(|x| F::from(*x as u64))
                .collect::<Vec<F>>(),
        );

        let pub_input = [expected_root];

        test_var_pub_input(synthesizer, &pub_input, &priv_input)
    }
}
