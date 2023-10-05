use crate::r1cs::R1CS;
use crate::spartan::commitment::Gens;
use crate::spartan::hyrax::{PolyEvalProof, PolyEvalProofInters};
use crate::spartan::ipa::{IPAInters, InnerProductProof};
use crate::spartan::polynomial::sparse_ml_poly::SparseMLPoly;
use crate::spartan::sumcheck::SumCheckProof;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ethers::prelude::*;

abigen!(
    SpartanVerifier,
    "out/SpartanVerifier.sol/SpartanVerifier.json"
);

pub fn from_u256<F: PrimeField>(x: U256) -> F {
    let mut bytes = [0u8; 32];
    x.to_big_endian(&mut bytes);
    F::from_be_bytes_mod_order(&bytes)
}

pub fn to_u256<F: Field>(x: F) -> U256 {
    U256::from_str_radix(&x.to_string(), 10).unwrap()
}

pub fn to_u256_vec<F: Field>(x: &[F]) -> Vec<U256> {
    x.iter().map(|e: &F| to_u256(*e)).collect()
}

pub fn to_evm_point<C: CurveGroup>(p: C) -> EvmAffinePoint {
    let affine = p.into_affine();
    if affine.is_zero() {
        EvmAffinePoint {
            x: U256::from(0),
            y: U256::from(0),
        }
    } else {
        EvmAffinePoint {
            x: to_u256(*affine.x().unwrap()),
            y: to_u256(*affine.y().unwrap()),
        }
    }
}

pub fn to_evm_points_vec<C: CurveGroup>(points: &[C]) -> Vec<EvmAffinePoint> {
    points.iter().map(|p| to_evm_point(*p)).collect()
}

pub fn build_ip_proof<C: CurveGroup>(
    ip_proof: InnerProductProof<C>,
    inters: IPAInters<C>,
) -> EvmInnerProductProof {
    EvmInnerProductProof {
        a: to_u256(ip_proof.a),
        y: to_u256(ip_proof.y),
        comm: to_evm_point(ip_proof.comm),
        l: to_evm_points_vec(&ip_proof.L_vec),
        r: to_evm_points_vec(&ip_proof.R_vec),
        s_ag_powers: to_evm_points_vec(&inters.sa_G_inters),
        s_bg_powers: to_evm_points_vec(&inters.sb_H_inters),
        bh_powers: to_evm_points_vec(&inters.b_H_inters),
    }
}

pub fn to_evm_poly_eval_proof<C: CurveGroup>(
    eval_proof: PolyEvalProof<C>,
    inters: PolyEvalProofInters<C>,
) -> EvmPolyEvalProof {
    EvmPolyEvalProof {
        y: to_u256(eval_proof.y),
        t: to_evm_points_vec(&eval_proof.T),
        ip_proof: build_ip_proof(eval_proof.inner_prod_proof, inters.ipa_inters),
        t_lpowers: to_evm_points_vec(&inters.T_prime_inters),
    }
}

pub fn build_evm_sumcheck_proof<C: CurveGroup>(
    sc_proof: SumCheckProof<C>,
    inters: IPAInters<C>,
) -> EvmSumCheckProof {
    let round_polys_coeffs = sc_proof
        .round_poly_coeffs
        .iter()
        .map(|coeffs| to_u256_vec(coeffs))
        .collect::<Vec<Vec<U256>>>();

    EvmSumCheckProof {
        round_polys_coeffs,
        blind_poly_sum: to_u256(sc_proof.blinder_poly_sum),
        blind_poly_eval_proof: build_ip_proof(sc_proof.blinder_poly_eval_proof, inters),
    }
}

pub trait ToEvmVal {
    type EvmVal;
    fn to_evm_val(&self) -> Self::EvmVal;
}

impl<F: PrimeField> ToEvmVal for SparseMLPoly<F> {
    type EvmVal = Vec<LagrangeEntry>;

    fn to_evm_val(&self) -> Self::EvmVal {
        self.evals
            .iter()
            .map(|e| LagrangeEntry {
                index: U256::from(e.0),
                val: to_u256(e.1),
            })
            .collect::<Vec<LagrangeEntry>>()
    }
}

impl<C: CurveGroup> ToEvmVal for Gens<C> {
    type EvmVal = EvmGens;
    fn to_evm_val(&self) -> Self::EvmVal {
        EvmGens {
            g: to_evm_points_vec(&self.G),
            h: vec![],
            u: to_evm_point(self.u.unwrap()),
        }
    }
}

impl<F: PrimeField> ToEvmVal for R1CS<F> {
    type EvmVal = EvmR1CS;

    fn to_evm_val(&self) -> Self::EvmVal {
        let A_mle = self.A.to_ml_extension();
        let B_mle = self.B.to_ml_extension();
        let C_mle = self.C.to_ml_extension();

        EvmR1CS {
            a: A_mle.to_evm_val(),
            b: B_mle.to_evm_val(),
            c: C_mle.to_evm_val(),
            z_len: U256::from(self.z_len()),
        }
    }
}

/*
impl ToEvmVal for Affine {
    type EvmVal = AffinePoint;
    fn to_evm_val(&self) -> Self::EvmVal {
        to_u256(self.to_affine().x)
    }
}
*/

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use ethers::signers::{Signer, Wallet};
    use ethers::solc::CompilerInput;
    use ethers::utils::AnvilInstance;
    use ethers::{
        providers::{Http, Provider},
        signers::LocalWallet,
    };
    use k256::ecdsa::SigningKey;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    fn is_debug() -> bool {
        let debug = std::env::var("DEBUG");
        debug.is_ok()
    }

    pub fn init_wallet(anvil: &AnvilInstance) -> Wallet<SigningKey> {
        if is_debug() {
            let wallet: LocalWallet =
                "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                    .parse::<LocalWallet>()
                    .unwrap()
                    .into();

            wallet.with_chain_id(31337u64)
        } else {
            let wallet: LocalWallet = anvil.keys()[0].clone().into();
            wallet.with_chain_id(anvil.chain_id())
        }
    }

    pub fn init_node(anvil: &AnvilInstance) -> String {
        if is_debug() {
            "http://localhost:8545".to_string()
        } else {
            anvil.endpoint()
        }
    }

    pub async fn deploy_contract(
        endpoint: String,
        wallet: LocalWallet,
        contract_name: &'static str,
    ) -> (H160, Arc<SignerMiddleware<Provider<Http>, LocalWallet>>) {
        let deploy_contract_timer = start_timer!(|| "Deploy contract");

        // 2. instantiate our wallet & anvil

        // 3. connect to the network
        let provider = Provider::<Http>::try_from(endpoint)
            .unwrap()
            .interval(Duration::from_millis(10u64));

        // let wallet = init_wallet();

        //let wallet = init_wallet();
        let client = Arc::new(SignerMiddleware::new(
            provider, // wallet.with_chain_id(31337u64),
            wallet,
        ));

        let source =
            Path::new(&env!("CARGO_MANIFEST_DIR")).join(format!("contracts/{}.sol", contract_name));
        let mut compiler_input = CompilerInput::new(source).unwrap();
        let compiler_input = compiler_input.first_mut().unwrap();
        compiler_input.settings.via_ir = Some(true);

        let compiled = Solc::default()
            .compile(compiler_input)
            .expect("Could not compile contracts");

        let (abi, bytecode, _runtime_bytecode) = compiled
            .find(contract_name)
            .expect("could not find contract")
            .into_parts_or_default();

        println!("Contract size: {} bytes", bytecode.len());

        // 5. create a factory which will be used to deploy instances of the contract
        let factory = ContractFactory::new(abi, bytecode, client.clone());
        let contract = factory.deploy(()).unwrap().send().await.unwrap();

        end_timer!(deploy_contract_timer);
        // CONTRACT_ADDRESS.set(contract.address()).unwrap();
        (contract.address(), client.clone())

        /*
        if CONTRACT_ADDRESS.initialized() {
            println!("Contract already deployed");
            CONTRACT_ADDRESS.get().unwrap().clone()
        } else {
            println!("Deploying contract");
            // let provider = init_provider();

            // 2. instantiate our wallet & anvil
            let anvil = Anvil::new().spawn();

            // 3. connect to the network
            let provider = Provider::<Http>::try_from(anvil.endpoint())
                .unwrap()
                .interval(Duration::from_millis(10u64));

            let wallet: LocalWallet = anvil.keys()[0].clone().into();

            // let wallet = init_wallet();

            //let wallet = init_wallet();
            let client = Arc::new(SignerMiddleware::new(
                provider,
                // wallet.with_chain_id(31337u64),
                wallet.with_chain_id(1u64),
            ));

            let source =
                Path::new(&env!("CARGO_MANIFEST_DIR")).join(format!("contracts/{}.sol", contract_name));
            let mut compiler_input = CompilerInput::new(source).unwrap();
            let compiler_input = compiler_input.first_mut().unwrap();
            compiler_input.settings.via_ir = Some(true);

            let compiled = Solc::default()
                .compile(compiler_input)
                .expect("Could not compile contracts");

            let (abi, bytecode, _runtime_bytecode) = compiled
                .find(contract_name)
                .expect("could not find contract")
                .into_parts_or_default();

            // 5. create a factory which will be used to deploy instances of the contract
            let factory = ContractFactory::new(abi, bytecode, client);
            let contract = factory.deploy(()).unwrap().send().await.unwrap();

            end_timer!(deploy_contract_timer);
            CONTRACT_ADDRESS.set(contract.address()).unwrap();
            contract.address()
        }
         */
    }
}
