use pathfinder_common::transaction::{ResourceBound, ResourceBounds};
use pathfinder_common::{
    casm_hash,
    contract_address,
    felt,
    public_key,
    sierra_hash,
    state_diff_commitment,
    CasmHash,
    ContractAddress,
    GasPrice,
    PublicKey,
    ResourceAmount,
    ResourcePricePerUnit,
    SierraHash,
    StateDiffCommitment,
};
use pathfinder_crypto::Felt;

/// All classes that are predeclared in the devnet.
pub const PREDECLARED_CLASSES: &[(&[u8], SierraHash)] = &[
    (CAIRO_1_ACCOUNT_CLASS, CAIRO_1_ACCOUNT_CLASS_HASH),
    (ETH_ERC20_CLASS, ETH_ERC20_CLASS_HASH),
    (STRK_ERC20_CLASS, STRK_ERC20_CLASS_HASH),
    (UDC_CLASS, UDC_CLASS_HASH),
];

/// Excludes accounts!
pub const PREDEPLOYED_CONTRACTS: &[(ContractAddress, SierraHash)] = &[
    (UDC_CONTRACT_ADDRESS, UDC_CLASS_HASH),
    (ETH_ERC20_CONTRACT_ADDRESS, ETH_ERC20_CLASS_HASH),
    (STRK_ERC20_CONTRACT_ADDRESS, STRK_ERC20_CLASS_HASH),
];

pub const ERC20S: &[(ContractAddress, &'static str, &'static str)] = &[
    (ETH_ERC20_CONTRACT_ADDRESS, ETH_ERC20_NAME, ETH_ERC20_SYMBOL),
    (
        STRK_ERC20_CONTRACT_ADDRESS,
        STRK_ERC20_NAME,
        STRK_ERC20_SYMBOL,
    ),
];

pub const CAIRO_1_ACCOUNT_CLASS: &[u8] =
    include_bytes!("./fixtures/account/OpenZeppelin/1.0.0/Account.cairo/Account.sierra");
pub const CAIRO_1_ACCOUNT_CLASS_HASH: SierraHash =
    sierra_hash!("0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564");

pub const ETH_ERC20_CLASS: &[u8] = include_bytes!("./fixtures/system/erc20_eth.sierra");
pub const ETH_ERC20_CLASS_HASH: SierraHash =
    sierra_hash!("0x9524a94b41c4440a16fd96d7c1ef6ad6f44c1c013e96662734502cd4ee9b1f");
pub const ETH_ERC20_CONTRACT_ADDRESS: ContractAddress =
    contract_address!("0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7");

pub const STRK_ERC20_CLASS: &[u8] = include_bytes!("./fixtures/system/erc20_strk.sierra");
pub const STRK_ERC20_CLASS_HASH: SierraHash =
    sierra_hash!("0x76791ef97c042f81fbf352ad95f39a22554ee8d7927b2ce3c681f3418b5206a");
pub const STRK_ERC20_CONTRACT_ADDRESS: ContractAddress =
    contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

// Original comment from starknet-rust-core: ERC20 contracts storage variables; available in source at https://github.com/starknet-io/starkgate-contracts
// Note (Chris): I wasn't able to find these values in the source
pub const ETH_ERC20_NAME: &str = "Ether";
pub const ETH_ERC20_SYMBOL: &str = "ETH";
pub const STRK_ERC20_NAME: &str = "StarkNet Token";
pub const STRK_ERC20_SYMBOL: &str = "STRK";

pub const UDC_CLASS: &[u8] = include_bytes!("./fixtures/system/udc_2.sierra");
pub const UDC_CLASS_HASH: SierraHash =
    sierra_hash!("0x01b2df6d8861670d4a8ca4670433b2418d78169c2947f46dc614e69f333745c8");
pub const UDC_CONTRACT_ADDRESS: ContractAddress =
    contract_address!("0x02ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125");

// As simple as possible to keep ECDSA happy.
pub const ACCOUNT_PRIVATE_KEY: Felt = Felt::ONE;
pub const ACCOUNT_PUBLIC_KEY: PublicKey =
    public_key!("0x01EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA");
pub const ACCOUNT_ADDRESS: ContractAddress =
    contract_address!("0x02334DE23F9C31EEF53826835D99537F5C3823B7DE60F5B605819BF2EA97C6CA");

/// https://github.com/OpenZeppelin/cairo-contracts/blob/89a450a88628ec3b86273f261b2d8d1ca9b1522b/src/account/interface.cairo#L7
pub const ISRC6_ID: Felt =
    felt!("0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd");

pub const HELLO_CLASS: &[u8] = include_bytes!("./fixtures/hello_starknet.sierra");
pub const HELLO_CLASS_HASH: SierraHash =
    sierra_hash!("0x0457EF47CFAA819D9FE1372E8957815CDBA2252ED3E42A15536A5A40747C8A00");
pub const HELLO_CASM_HASH: CasmHash =
    casm_hash!("0x0071411E420C6D4237454AD997676341D8FBFDE4256888B31F34204AB7ED912F");

/// Some nonzero gas price
pub const GAS_PRICE: GasPrice = GasPrice(1_000_000_000);
/// WEI to FRI conversion rate is 1:1 for simplicity, so ETH to FRI conversion
/// rate is 1:1e18
pub const ETH_TO_FRI_RATE: u128 = 1_000_000_000_000_000_000;
/// Some nonzero resource bounds
pub const RESOURCE_BOUNDS: ResourceBounds = ResourceBounds {
    l1_gas: ResourceBound {
        max_amount: ResourceAmount(1_000_000),
        max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
    },
    l2_gas: ResourceBound {
        max_amount: ResourceAmount(1_000_000),
        max_price_per_unit: ResourcePricePerUnit(1_000_000_000),
    },
    l1_data_gas: None,
};

pub const BLOCK_0_COMMITMENT: StateDiffCommitment =
    state_diff_commitment!("0x07065AC2DCB09AFCBE485B270FED390B4F45BB9F8360D6D7B2A190272B885257");
pub const BLOCK_1_COMMITMENT: StateDiffCommitment =
    state_diff_commitment!("0x046C66069A1C2C2FA09026C5E55A769C11A1BC2BE9CBDA43237EB4BA54C40C9F");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devnet::class::{preprocess_sierra, PrepocessedSierra};
    use crate::devnet::contract::compute_address;
    use crate::devnet::utils::compute_public_key;

    #[test]
    fn derived_account_values_match_fixture() {
        assert_eq!(
            compute_public_key(ACCOUNT_PRIVATE_KEY).unwrap(),
            ACCOUNT_PUBLIC_KEY,
        );
        assert_eq!(
            compute_address(CAIRO_1_ACCOUNT_CLASS_HASH, ACCOUNT_PUBLIC_KEY).unwrap(),
            ACCOUNT_ADDRESS,
        );
    }

    #[test]
    fn derived_hello_contract_values_match_fixture() {
        let PrepocessedSierra {
            sierra_class_hash,
            casm_hash_v2,
            ..
        } = preprocess_sierra(HELLO_CLASS, None).unwrap();

        assert_eq!(sierra_class_hash, HELLO_CLASS_HASH);
        assert_eq!(casm_hash_v2, HELLO_CASM_HASH);
    }
}
