#[cfg(test)]
mod tests {
    use super::super::utils::test_utils::*;
    use super::super::utils::*;
    use crate::spartan::spartan::Spartan;
    use crate::wasm::prelude::Transcript;
    use crate::{constraint_system::ConstraintSystem, mock_circuit};
    use ark_std::{end_timer, start_timer};
    use ethers::prelude::*;
    use ethers::utils::Anvil;

    type F = ark_secq256k1::Fr;
    type Curve = ark_secq256k1::Projective;

    #[tokio::test]
    async fn test_spartan_verifier() {
        // Init the EVM provider
        let anvil = Anvil::new().spawn();
        let wallet = init_wallet(&anvil);
        let endpoint = init_node(&anvil);

        // Deploy the contract
        let (contract_address, client) = deploy_contract(endpoint, wallet, "SpartanVerifier").await;
        let verifier_contract = SpartanVerifier::new(contract_address, client.clone());

        // Prepare the circuit
        let num_cons = 2usize.pow(4);
        let synthesizer = mock_circuit(num_cons);
        let mut cs = ConstraintSystem::new();
        cs.set_constraints(&synthesizer);

        let r1cs = cs.to_r1cs();
        let priv_input = vec![F::from(1), F::from(2)];
        let pub_input = vec![priv_input[0] * priv_input[1]];

        let witness = cs.gen_witness(synthesizer, &pub_input, &priv_input);

        // Generate a Spartan proof
        let spartan = Spartan::<Curve>::new(r1cs.z_len());
        let mut transcript = Transcript::new(b"spartan_verifier_test");
        let prover_timer = start_timer!(|| "Prove");
        let (proof, _) = spartan.prove(&r1cs, &witness, &pub_input, &mut transcript);
        end_timer!(prover_timer);

        // Verify the proof
        let mut verifier_transcript = Transcript::new(b"spartan_verifier_test");
        let inters = spartan
            .verify(&r1cs, &proof, &mut verifier_transcript, true)
            .unwrap();

        // Submit the proof

        let full_proof = FullProof {
            sc_proof_1: build_evm_sumcheck_proof(proof.sc_proof_1, inters.sc1_inters),
            sc_proof_2: build_evm_sumcheck_proof(proof.sc_proof_2, inters.sc2_inters),
            z_eval_proof: to_evm_poly_eval_proof(proof.z_eval_proof, inters.z_eval_inters),
            v_a: to_u256(proof.v_A),
            v_b: to_u256(proof.v_B),
            v_c: to_u256(proof.v_C),
            public_input: to_u256_vec(&pub_input),
        };

        let send_tx_timer = start_timer!(|| "Send tx");
        let result = verifier_contract
            .submit_proof(full_proof.clone())
            .send()
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        end_timer!(send_tx_timer);

        println!(
            "Gas used for proof submission: {:?}",
            result.gas_used.unwrap()
        );

        let tx = client
            .get_transaction(result.transaction_hash)
            .await
            .unwrap()
            .unwrap();

        println!("Circuit:");
        println!("  constraints: {:?}", cs.num_constraints.unwrap());
        println!("  wires : {:?}", cs.num_vars());
        println!("calldata size: {:?}", tx.input.len());

        let auxiliaries = OpeningVerifyAuxilaries {
            msm_index: U256::from(0),
            step: 0,
        };

        let gens = spartan.hyrax.ipa.gens.clone().to_evm_val();

        // Verify the proof
        let mut tx =
            verifier_contract.verify_proof(full_proof, r1cs.to_evm_val(), 0, auxiliaries, gens);
        tx.tx.set_gas(100000000u64);

        let result = tx.send().await.unwrap().await.unwrap().unwrap();
        println!("Gas used for verification: {:?}", result.gas_used.unwrap());
    }
}
