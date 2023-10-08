mod secp256k1_test;
mod spartan_verifier_test;
mod utils;
use crate::{
    r1cs::R1CS,
    wasm::wasm_deps::{Spartan, SpartanProof, Transcript},
    ScalarField,
};
use ark_ec::CurveGroup;
use ethers::prelude::*;
use std::sync::Arc;
pub use utils::*;

pub fn generate_submit_proof_input<C: CurveGroup>(
    proof: SpartanProof<C>,
    r1cs: &R1CS<ScalarField<C>>,
    contract_address: &[u8],
) -> Vec<u8> {
    let spartan = Spartan::<C>::new(r1cs.z_len());

    let mut transcript = Transcript::new(b"Spartan");

    // Compute the intermediate values
    let inters = spartan
        .verify(&r1cs, &proof, &mut transcript, true)
        .unwrap();

    let contract_address: [u8; 20] = contract_address.try_into().unwrap();
    let contract_address = H160::from(contract_address);

    // 3. connect to the network
    let provider = Provider::<Http>::try_from("http://localhost:8545".to_string()).unwrap();

    // Dummy wallet
    let mut wallet: LocalWallet =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse::<LocalWallet>()
            .unwrap()
            .into();
    wallet = wallet.with_chain_id(31337u64);

    let client = Arc::new(SignerMiddleware::new(
        provider, // wallet.with_chain_id(31337u64),
        wallet,
    ));

    let verifier_contract = SpartanVerifier::new(contract_address, client);

    let full_proof = FullProof {
        sc_proof_1: build_evm_sumcheck_proof(proof.sc_proof_1, inters.sc1_inters),
        sc_proof_2: build_evm_sumcheck_proof(proof.sc_proof_2, inters.sc2_inters),
        z_eval_proof: to_evm_poly_eval_proof(proof.z_eval_proof, inters.z_eval_inters),
        v_a: to_u256(proof.v_A),
        v_b: to_u256(proof.v_B),
        v_c: to_u256(proof.v_C),
        public_input: to_u256_vec(&proof.pub_input),
    };

    // Construct the transaction data
    let tx: Eip1559TransactionRequest =
        verifier_contract.submit_proof(full_proof.clone()).tx.into();

    let tx_data = tx.data.unwrap().0;
    // Construct the transaction data
    tx_data.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::frontend::constraint_system::ConstraintSystem;
    use crate::mock_circuit;
    use crate::spartan::spartan::Spartan;

    type F = ark_secq256k1::Fr;
    type Curve = ark_secq256k1::Projective;

    #[test]
    fn test_generate_submit_proof_input() {
        let num_cons = 2usize.pow(5);
        let synthesizer = mock_circuit(num_cons);
        let mut cs = ConstraintSystem::<F>::new();
        cs.set_constraints(&synthesizer);

        let priv_input = vec![F::from(1), F::from(2)];
        let pub_input = vec![priv_input[0] * priv_input[1]];

        let witness = cs.gen_witness(synthesizer, &pub_input, &priv_input);

        let r1cs = cs.to_r1cs();

        let spartan = Spartan::<Curve>::new(r1cs.z_len());
        let mut transcript = Transcript::new(b"Spartan");
        let (proof, _) = spartan.prove(&r1cs, &witness, &pub_input, &mut transcript);

        let _input = generate_submit_proof_input(
            proof,
            &r1cs,
            &hex::decode("5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
        );
    }
}
