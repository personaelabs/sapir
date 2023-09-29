#![allow(non_snake_case)]
mod secp256k1_test;
mod spartan_verifier_test;
mod utils;
use ethers::prelude::*;
use spartan::{
    r1cs::R1CS,
    wasm::wasm_deps::{CanonicalDeserialize, Hyrax, Spartan, SpartanProof, Transcript},
};
use std::sync::Arc;
pub use utils::*;
use wasm_bindgen::prelude::wasm_bindgen;

type Curve = spartan::ark_secq256k1::Projective;
type F = spartan::ark_secq256k1::Fr;

#[wasm_bindgen]
pub fn generate_submit_proof_input(
    proof_ser: &[u8],
    r1cs_ser: &[u8],
    contract_address: &[u8],
) -> Vec<u8> {
    // BGM
    // Deserialize the proof
    let proof = SpartanProof::<Curve>::deserialize_compressed(proof_ser).unwrap();

    // TODO: Make this a global variable so we only need to load it once.
    let r1cs = R1CS::<F>::deserialize_compressed(r1cs_ser).unwrap();

    let spartan = Spartan::<Curve>::new();
    let hyrax = Hyrax::new(r1cs.z_len());

    let mut transcript = Transcript::new(b"");

    // Compute the intermediate values
    let inters = spartan
        .verify(&r1cs, &hyrax, &proof, &mut transcript, true)
        .unwrap();

    let contract_address: [u8; 20] = contract_address.try_into().unwrap();
    let contract_address = H160::from(contract_address);

    // 3. connect to the network
    let provider = Provider::<Http>::try_from("".to_string()).unwrap();

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
