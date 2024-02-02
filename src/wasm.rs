pub mod prelude {
    // Re-export the dependencies that are used in the wasm module
    pub use crate::frontend::constraint_system::{CircuitMeta, ConstraintSystem};
    pub use crate::r1cs::R1CS;
    pub use crate::spartan::hyrax::Hyrax;
    pub use crate::spartan::spartan::{Spartan, SpartanProof};
    pub use crate::spartan::transcript::Transcript;
    pub use crate::ScalarField;
    pub use ark_ff::Field;
    pub use ark_ff::PrimeField;
    pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    pub use console_error_panic_hook;
    pub use std::sync::Mutex;
    pub use wasm_bindgen;
    pub use wasm_bindgen::prelude::*;
    pub use wasm_bindgen::JsValue;
    pub use web_sys;

    #[allow(dead_code)]
    pub fn to_felts<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
        bytes
            .chunks_exact(32)
            .map(|x| F::from_be_bytes_mod_order(x))
            .collect::<Vec<F>>()
    }
}

#[allow(unused_imports)]
use prelude::*;

#[macro_export]
macro_rules! embed_to_wasm {
    ($synthesizer:expr, $curve:ty, $label:expr) => {
        static CIRCUIT: Mutex<R1CS<ScalarField<$curve>>> = Mutex::new(R1CS::empty());

        static CONSTRAINT_SYSTEM: Mutex<ConstraintSystem<ScalarField<$curve>>> =
            Mutex::new(ConstraintSystem::new());

        // ################################
        // Expose the following functions to the wasm runtime
        // ################################

        #[wasm_bindgen]
        pub fn init_panic_hook() {
            console_error_panic_hook::set_once();
        }

        #[wasm_bindgen]
        pub fn prepare() {
            // ################################
            // Load the circuit
            // ################################

            let mut circuit = CIRCUIT.lock().unwrap();

            let mut cs = CONSTRAINT_SYSTEM.lock().unwrap();
            cs.set_constraints(&$synthesizer);
            *circuit = cs.to_r1cs();

            #[cfg(target_arch = "wasm32")]
            {
                web_sys::console::log_1(&JsValue::from_str("Num constraints:"));
                web_sys::console::log_1(&JsValue::from_f64(cs.num_constraints.unwrap() as f64));
            };
        }

        #[wasm_bindgen]
        pub fn prove(pub_input: &[u8], priv_input: &[u8]) -> Vec<u8> {
            let pub_input = to_felts(pub_input);
            let priv_input = to_felts(priv_input);

            let circuit = CIRCUIT.lock().unwrap().clone();

            let mut cs = CONSTRAINT_SYSTEM.lock().unwrap();
            let witness = cs.gen_witness($synthesizer, &pub_input, &priv_input);

            assert!(cs.is_sat(&witness, &pub_input));

            // Generate the proof
            let spartan = Spartan::<$curve>::new($label, circuit);

            let proof = spartan.prove(&witness, &pub_input);

            let mut compressed_bytes = Vec::new();
            proof.0.serialize_compressed(&mut compressed_bytes).unwrap();
            compressed_bytes
        }

        #[wasm_bindgen]
        pub fn verify(proof_ser: &[u8]) -> bool {
            let proof = SpartanProof::<$curve>::deserialize_compressed(proof_ser).unwrap();
            let circuit = CIRCUIT.lock().unwrap().clone();

            let spartan = Spartan::new($label, circuit);
            spartan.verify(&proof, false);

            true
        }

        /*
        #[wasm_bindgen]
        pub fn generate_tx_input(proof_ser: &[u8], contract_address: &[u8]) -> Vec<u8> {
            let proof = SpartanProof::<$curve>::deserialize_compressed(proof_ser).unwrap();

            let circuit = CIRCUIT.lock().unwrap().clone();

            generate_submit_proof_input(proof, &circuit, contract_address)
        }
         */
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::test_utils::mock_circuit;
    use crate::timer::{timer_end, timer_start};
    use crate::ScalarField;
    use ark_ff::{BigInteger, PrimeField};
    use std::panic;

    type Curve = ark_secq256k1::Projective;
    type F = ark_secq256k1::Fr;

    #[test]
    fn test_to_felts() {
        let n = 3;
        let felts = (0..n).map(|i| F::from(i)).collect::<Vec<F>>();
        let felt_bytes = felts
            .iter()
            .map(|x| x.into_bigint().to_bytes_be())
            .flatten()
            .collect::<Vec<u8>>();

        let felts_recovered = to_felts::<F>(&felt_bytes);
        assert_eq!(felts, felts_recovered);
    }

    const NUM_CONS: usize = 2usize.pow(4);
    embed_to_wasm!(mock_circuit(NUM_CONS), Curve, b"test_prove");

    fn prove_and_verify(pub_input: &[F], priv_input: &[F]) {
        let pub_input_bytes = pub_input
            .iter()
            .map(|x| x.into_bigint().to_bytes_be())
            .flatten()
            .collect::<Vec<u8>>();

        let priv_input_bytes = priv_input
            .iter()
            .map(|x| x.into_bigint().to_bytes_be())
            .flatten()
            .collect::<Vec<u8>>();

        let prove_timer = timer_start("Proving time");
        let proof_bytes = prove(&pub_input_bytes, &priv_input_bytes);
        timer_end(prove_timer);

        let verify_timer = timer_start("Verification time");
        assert!(verify(&proof_bytes));
        timer_end(verify_timer);
    }

    #[test]
    fn test_prove() {
        let priv_input = [F::from(3), F::from(4)];
        let pub_input = [priv_input[0] * priv_input[1]];

        prepare();

        prove_and_verify(&pub_input, &priv_input);

        let mut invalid_pub_input = pub_input;
        invalid_pub_input[0] = F::from(0);

        // Test with invalid public input
        let result = panic::catch_unwind(|| prove_and_verify(&invalid_pub_input, &priv_input));
        assert!(result.is_err());
    }
}
