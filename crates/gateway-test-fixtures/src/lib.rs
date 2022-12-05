macro_rules! str_fixture {
    ($file_name:literal) => {
        include_str!(concat!("../fixtures/", $file_name))
    };
}

macro_rules! bytes_fixture {
    ($file_name:literal) => {
        include_bytes!(concat!("../fixtures/", $file_name))
    };
}

pub mod v0_8_2 {
    pub mod block {
        pub const GENESIS: &str = str_fixture!("0.8.2/block/genesis.json");
        pub const NUMBER_1716: &str = str_fixture!("0.8.2/block/1716.json");
        pub const PENDING: &str = str_fixture!("0.8.2/block/pending.json");
    }

    pub mod transaction {
        pub const INVOKE: &str = str_fixture!("0.8.2/txn/invoke.json");
    }
}

pub mod v0_9_0 {
    pub mod block {
        pub const GENESIS: &str = str_fixture!("0.9.0/block/genesis.json");
        pub const NUMBER_1716: &str = str_fixture!("0.9.0/block/1716.json");
        pub const NUMBER_90000: &str = str_fixture!("0.9.0/block/90000.json");
        pub const NUMBER_156000: &str = str_fixture!("0.9.0/block/156000.json");
        pub const NUMBER_231579: &str = str_fixture!("0.9.0/block/231579.json");
        pub const PENDING: &str = str_fixture!("0.9.0/block/pending.json");
    }

    pub mod transaction {
        pub const DECLARE: &str = str_fixture!("0.9.0/txn/declare.json");
        pub const DEPLOY: &str = str_fixture!("0.9.0/txn/deploy.json");
        pub const INVOKE: &str = str_fixture!("0.9.0/txn/invoke.json");
        pub const STATUS: &str = str_fixture!("0.9.0/txn/status.json");
    }
}

pub mod v0_9_1 {
    pub mod state_update {
        pub const GENESIS: &str = str_fixture!("0.9.1/state-update/genesis.json");
        pub const NUMBER_315700: &str = str_fixture!("0.9.1/state-update/315700.json");
        pub const PENDING: &str = str_fixture!("0.9.1/state-update/pending.json");
    }
}

pub mod v0_10_1 {
    pub mod add_transaction {
        pub const DEPLOY_ACCOUNT_REQUEST: &str =
            str_fixture!("0.10.1/add-transaction/deploy-account-request.json");
        pub const DEPLOY_ACCOUNT_RESPONSE: &str =
            str_fixture!("0.10.1/add-transaction/deploy-account-response.json");
    }
}

pub mod add_transaction {
    pub const DEPLOY_OPENZEPPELIN_ACCOUNT: &str =
        str_fixture!("add-transaction/deploy-openzeppelin-account.json");
    pub const DEPLOY_TRANSACTION: &str = str_fixture!("add-transaction/deploy-transaction.json");
    pub const INVOKE_CONTRACT_WITH_SIGNATURE: &str =
        str_fixture!("add-transaction/invoke-contract-with-signature.json");
}

pub mod integration {
    pub mod block {
        pub const NUMBER_1: &str = str_fixture!("integration/block/1.json");
        pub const NUMBER_192844: &str = str_fixture!("integration/block/192844.json");
        pub const NUMBER_216171: &str = str_fixture!("integration/block/216171.json");
        pub const NUMBER_216591: &str = str_fixture!("integration/block/216591.json");
        pub const NUMBER_228457: &str = str_fixture!("integration/block/228457.json");
        pub const PENDING: &str = str_fixture!("integration/block/pending.json");
    }

    pub mod state_update {
        pub const NUMBER_216572: &str = str_fixture!("integration/state-update/216572.json");
    }
}

pub mod zstd_compressed {
    pub const CONTRACT_DEFINITION: &[u8] = bytes_fixture!("contract_definition.json.zst");
    pub const DUMMY_ACCOUNT: &[u8] = bytes_fixture!("dummy_account.json.zst");
}

pub mod testnet {
    use pathfinder_common::{
        starkhash, CallParam, ClassHash, ContractAddress, EntryPoint, StarknetBlockHash,
        StarknetBlockNumber, StarknetTransactionHash, StorageAddress,
    };
    use stark_hash::StarkHash;
    use starknet_gateway_types::request::{BlockHashOrTag, BlockNumberOrTag};

    pub const GENESIS_BLOCK_NUMBER: BlockNumberOrTag =
        BlockNumberOrTag::Number(StarknetBlockNumber::GENESIS);
    pub const INVALID_BLOCK_NUMBER: BlockNumberOrTag =
        BlockNumberOrTag::Number(StarknetBlockNumber::MAX);
    pub const GENESIS_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash(
        starkhash!("07d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"),
    ));
    pub const INVALID_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash(
        starkhash!("06d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"),
    ));
    pub const PRE_DEPLOY_CONTRACT_BLOCK_HASH: BlockHashOrTag =
        BlockHashOrTag::Hash(StarknetBlockHash(starkhash!(
            "05ef884a311df4339c8df791ce19bf305d7cf299416666b167bc56dd2d1f435f"
        )));
    pub const INVOKE_CONTRACT_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash(
        starkhash!("03871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"),
    ));
    pub const VALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash(starkhash!(
        "0493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24"
    ));
    pub const INVALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash(starkhash!(
        "0393d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24"
    ));
    pub const VALID_CONTRACT_ADDR: ContractAddress = ContractAddress::new_or_panic(starkhash!(
        "06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"
    ));
    pub const INVALID_CONTRACT_ADDR: ContractAddress = ContractAddress::new_or_panic(starkhash!(
        "05fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"
    ));
    pub const VALID_ENTRY_POINT: EntryPoint = EntryPoint(starkhash!(
        "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
    ));
    pub const INVALID_ENTRY_POINT: EntryPoint = EntryPoint(StarkHash::ZERO);
    pub const VALID_KEY: StorageAddress = StorageAddress::new_or_panic(starkhash!(
        "0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091"
    ));
    pub const VALID_KEY_DEC: &str =
        "916907772491729262376534102982219947830828984996257231353398618781993312401";
    pub const VALID_CALL_DATA: [CallParam; 1] = [CallParam(starkhash!("04d2"))];
    /// Class hash for VALID_CONTRACT_ADDR
    pub const VALID_CLASS_HASH: ClassHash = ClassHash(starkhash!(
        "021a7f43387573b68666669a0ed764252ce5367708e696e31967764a90b429c2"
    ));
    pub const INVALID_CLASS_HASH: ClassHash = ClassHash(starkhash!(
        "031a7f43387573b68666669a0ed764252ce5367708e696e31967764a90b429c2"
    ));
}
