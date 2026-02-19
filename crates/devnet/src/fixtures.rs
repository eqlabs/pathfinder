use pathfinder_common::{
    casm_hash,
    class_hash,
    contract_address,
    felt,
    public_key,
    CasmHash,
    ClassHash,
    ContractAddress,
    PublicKey,
};
use pathfinder_crypto::Felt;

/// All classes that are predeclared in the devnet.
pub const PREDECLARED_CLASSES: &[(&[u8], ClassHash)] = &[
    (CAIRO_1_ACCOUNT_CLASS, CAIRO_1_ACCOUNT_CLASS_HASH),
    (ETH_ERC20_CLASS, ETH_ERC20_CLASS_HASH),
    (STRK_ERC20_CLASS, STRK_ERC20_CLASS_HASH),
    (UDC_CLASS, UDC_CLASS_HASH),
];

/// Excludes accounts!
pub const PREDEPLOYED_CONTRACTS: &[(ContractAddress, ClassHash)] = &[
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
pub const CAIRO_1_ACCOUNT_CLASS_HASH: ClassHash =
    class_hash!("0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564");

pub const ETH_ERC20_CLASS: &[u8] = include_bytes!("./fixtures/system/erc20_eth.sierra");
pub const ETH_ERC20_CLASS_HASH: ClassHash =
    class_hash!("0x9524a94b41c4440a16fd96d7c1ef6ad6f44c1c013e96662734502cd4ee9b1f");
pub const ETH_ERC20_CONTRACT_ADDRESS: ContractAddress =
    contract_address!("0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7");

pub const STRK_ERC20_CLASS: &[u8] = include_bytes!("./fixtures/system/erc20_strk.sierra");
pub const STRK_ERC20_CLASS_HASH: ClassHash =
    class_hash!("0x76791ef97c042f81fbf352ad95f39a22554ee8d7927b2ce3c681f3418b5206a");
pub const STRK_ERC20_CONTRACT_ADDRESS: ContractAddress =
    contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

// Original comment from starknet-rust-core: ERC20 contracts storage variables; available in source at https://github.com/starknet-io/starkgate-contracts
// Note (Chris): I wasn't able to find these values in the source
pub const ETH_ERC20_NAME: &str = "Ether";
pub const ETH_ERC20_SYMBOL: &str = "ETH";
pub const STRK_ERC20_NAME: &str = "StarkNet Token";
pub const STRK_ERC20_SYMBOL: &str = "STRK";

pub const UDC_CLASS: &[u8] = include_bytes!("./fixtures/system/udc_2.sierra");
pub const UDC_CLASS_HASH: ClassHash =
    class_hash!("0x01b2df6d8861670d4a8ca4670433b2418d78169c2947f46dc614e69f333745c8");
pub const UDC_CONTRACT_ADDRESS: ContractAddress =
    contract_address!("0x02ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125");

pub const CHARGEABLE_ACCOUNT_PUBLIC_KEY: PublicKey =
    public_key!("0x4C37AB4F0994879337BFD4EAD0800776DB57DA382B8ED8EFAA478C5D3B942A4");
pub const CHARGEABLE_ACCOUNT_PRIVATE_KEY: Felt = felt!("0x5FB2959E3011A873A7160F5BB32B0ECE");
pub const CHARGEABLE_ACCOUNT_ADDRESS: ContractAddress =
    contract_address!("0x1CAF2DF5ED5DDE1AE3FAEF4ACD72522AC3CB16E23F6DC4C7F9FAED67124C511");

/// https://github.com/OpenZeppelin/cairo-contracts/blob/89a450a88628ec3b86273f261b2d8d1ca9b1522b/src/account/interface.cairo#L7
pub const ISRC6_ID: Felt =
    felt!("0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd");

pub const HELLO_CLASS: &[u8] = include_bytes!("./fixtures/hello_starknet.sierra");
pub const HELLO_CLASS_HASH: ClassHash =
    class_hash!("0x0457EF47CFAA819D9FE1372E8957815CDBA2252ED3E42A15536A5A40747C8A00");
pub const HELLO_CASM_HASH: CasmHash =
    casm_hash!("0x0071411E420C6D4237454AD997676341D8FBFDE4256888B31F34204AB7ED912F");
