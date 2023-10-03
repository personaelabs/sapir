#[cfg(test)]
mod tests {
    use super::super::utils::test_utils::*;
    use super::super::{from_u256, to_u256};
    use crate::ark_ec::{CurveGroup, Group};
    use crate::ark_ff::Field;
    use crate::ark_secq256k1::{Affine, Fq, Fr, Projective};
    use ethers::prelude::*;
    use ethers::utils::Anvil;

    abigen!(Secq256k1, "out/Secq256k1.sol/Secq256k1.json");

    fn to_evm_point(p: Projective) -> EvmProjectivePoint {
        EvmProjectivePoint {
            x: to_u256(p.x),
            y: to_u256(p.y),
            z: to_u256(p.z),
        }
    }

    fn from_affine(p: Affine) -> EvmProjectivePoint {
        EvmProjectivePoint {
            x: to_u256(p.x),
            y: to_u256(p.y),
            z: U256::from(1),
        }
    }

    fn to_affine(x: U256, y: U256, z: U256) -> (Fq, Fq) {
        let mut a: Fq = from_u256(x);
        let mut b: Fq = from_u256(y);
        let z_inv = from_u256::<Fq>(z).inverse().unwrap();

        a = a * z_inv;
        b = b * z_inv;

        (a, b)
    }

    async fn deploy_secq256k1(
        endpoint: String,
        wallet: LocalWallet,
    ) -> Secq256k1<SignerMiddleware<Provider<Http>, LocalWallet>> {
        let (contract_address, client) = deploy_contract(endpoint, wallet, "Secq256k1").await;
        Secq256k1::new(contract_address, client)
    }

    #[tokio::test]
    async fn test_secq256k1_double() {
        let anvil = Anvil::new().spawn();
        let wallet = init_wallet(&anvil);
        let endpoint = init_node(&anvil);

        let secq256k1 = deploy_secq256k1(endpoint, wallet).await;

        let p = Projective::generator();
        let evm_point = to_evm_point(p);

        let expected = (p + p).into_affine();
        let (result_x, result_y, result_z) = secq256k1
            .double(evm_point.x, evm_point.y, evm_point.z)
            .call()
            .await
            .unwrap();

        let result_affine = to_affine(result_x, result_y, result_z);
        assert_eq!(result_affine, (expected.x, expected.y));
    }

    #[tokio::test]
    async fn test_secq256k1_add() {
        let anvil = Anvil::new().spawn();
        let wallet = init_wallet(&anvil);
        let endpoint = init_node(&anvil);
        let secq256k1 = deploy_secq256k1(endpoint, wallet).await;

        let p1 = Projective::generator();
        let p2 = (Projective::generator() * Fr::from(33u32)).into_affine();
        let evm_p1 = to_evm_point(p1);
        let evm_p2 = from_affine(p2);

        let result = secq256k1.add(evm_p1, evm_p2).call().await.unwrap();

        let expected = (p1 + p2).into_affine();
        let result_affine = to_affine(result.x, result.y, result.z);
        assert_eq!(result_affine, (expected.x, expected.y));
    }

    #[tokio::test]
    async fn test_secq256k1_mul() {
        let anvil = Anvil::new().spawn();
        let wallet = init_wallet(&anvil);
        let endpoint = init_node(&anvil);
        let secq256k1 = deploy_secq256k1(endpoint, wallet).await;

        let p = Projective::generator();
        let scalar = Fr::from(333333333u32);
        let evm_p = to_evm_point(p);

        let result = secq256k1.mul(evm_p, to_u256(scalar)).call().await.unwrap();

        let expected = (p * scalar).into_affine();
        let result_affine = to_affine(result.x, result.y, result.z);
        assert_eq!(result_affine, (expected.x, expected.y));
    }
}
