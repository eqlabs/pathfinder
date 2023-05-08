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

pub mod old {
    pub mod block {
        pub const NUMBER_192: &str = str_fixture!("old/block/192.json");
    }
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

pub mod v0_10_1 {
    pub mod add_transaction {
        pub const DEPLOY_ACCOUNT_REQUEST: &str =
            str_fixture!("0.10.1/add-transaction/deploy-account-request.json");
        pub const DEPLOY_ACCOUNT_RESPONSE: &str =
            str_fixture!("0.10.1/add-transaction/deploy-account-response.json");
    }
}

pub mod v0_11_0 {
    pub mod state_update {
        pub const GENESIS: &str = str_fixture!("0.11.0/state-update/genesis.json");
        pub const NUMBER_315700: &str = str_fixture!("0.11.0/state-update/315700.json");
        pub const PENDING: &str = str_fixture!("0.11.0/state-update/pending.json");
    }

    /// Some of the following transactions are "as of" 0.11.0 and not really
    /// introduced in the chain in 0.11.0
    pub mod transaction {
        pub mod declare {
            pub mod v1 {
                pub const BLOCK_463319: &str =
                    str_fixture!("0.11.0/transaction/declare_v1_block_463319.json");
                pub const BLOCK_797215: &str =
                    str_fixture!("0.11.0/transaction/declare_v1_block_797215.json");
            }

            pub mod v2 {
                pub const BLOCK_797220: &str =
                    str_fixture!("0.11.0/transaction/declare_v2_block_797220.json");
            }
        }

        pub mod deploy {
            pub mod v0 {
                /// First deploy on testnet
                pub const GENESIS: &str = str_fixture!("0.11.0/transaction/deploy_v0_genesis.json");
            }

            pub mod v1 {
                /// First deploy on testnet2, hash was calculated using chain id of testnet (goerli)
                pub const GENESIS_TESTNET2: &str =
                    str_fixture!("0.11.0/transaction/deploy_v1_genesis_testnet2.json");

                /// Last deploy on testnet
                pub const BLOCK_485004: &str =
                    str_fixture!("0.11.0/transaction/deploy_v1_block_485004.json");
            }
        }

        pub mod deploy_account {
            pub mod v1 {
                pub const BLOCK_375919: &str =
                    str_fixture!("0.11.0/transaction/deploy_account_v1_block_375919.json");
                pub const BLOCK_797K: &str =
                    str_fixture!("0.11.0/transaction/deploy_account_v1_block_797k.json");
            }
        }

        pub mod invoke {
            pub mod v0 {
                pub const GENESIS: &str = str_fixture!("0.11.0/transaction/invoke_v0_genesis.json");
                // Invoke v0 with entry point type L1 handler later served
                // as an L1 handler transaction
                pub const BLOCK_854_IDX_96: &str =
                    str_fixture!("0.11.0/transaction/invoke_v0_block_854_idx_96.json");
            }
            pub mod v1 {
                pub const BLOCK_420K: &str =
                    str_fixture!("0.11.0/transaction/invoke_v1_block_420k.json");
                pub const BLOCK_790K: &str =
                    str_fixture!("0.11.0/transaction/invoke_v1_block_790k.json");
            }
        }

        pub mod l1_handler {
            pub mod v0 {
                // Former Invoke v0 with entry point type L1 handler later served
                // as an L1 handler transaction
                pub const BLOCK_854_IDX_96: &str =
                    str_fixture!("0.11.0/transaction/l1_handler_v0_block_854_idx_96.json");
                pub const BLOCK_1564: &str =
                    str_fixture!("0.11.0/transaction/l1_handler_v0_block_1564.json");
                pub const BLOCK_272866: &str =
                    str_fixture!("0.11.0/transaction/l1_handler_v0_block_272866.json");
                pub const BLOCK_790K: &str =
                    str_fixture!("0.11.0/transaction/l1_handler_v0_block_790k.json");
            }
        }
    }
}

pub mod add_transaction {
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
        pub const NUMBER_285915: &str = str_fixture!("integration/block/285915.json");
        pub const PENDING: &str = str_fixture!("integration/block/pending.json");
    }

    pub mod state_update {
        // Contains declared_classes from 0.11.0
        pub const NUMBER_283364: &str = str_fixture!("integration/state-update/283364.json");
        // Contains replaced_classes from 0.11.0
        pub const NUMBER_283428: &str = str_fixture!("integration/state-update/283428.json");
    }
}

pub mod zstd_compressed_contracts {
    use pathfinder_common::{felt, ClassHash};

    pub const CONTRACT_DEFINITION: &[u8] = bytes_fixture!("contracts/contract_definition.json.zst");
    pub const DUMMY_ACCOUNT: &[u8] = bytes_fixture!("contracts/dummy_account.json.zst");
    pub const DUMMY_ACCOUNT_CLASS_HASH: ClassHash = ClassHash(felt!(
        "0x0791563da22895f1e398b689866718346106c0cc71207a4ada68e6687ce1badf"
    ));
    // https://external.integration.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x4ae0618c330c59559a59a27d143dd1c07cd74cf4e5e5a7cd85d53c6bf0e89dc
    pub const INTEGRATION_TEST: &[u8] = bytes_fixture!("contracts/integration-test.json.zst");
    // https://alpha4.starknet.io/feeder_gateway/get_full_contract?contractAddress=0546BA9763D33DC59A070C0D87D94F2DCAFA82C4A93B5E2BF5AE458B0013A9D3
    pub const GOERLI_GENESIS: &[u8] = bytes_fixture!("contracts/goerli-genesis.json.zst");
    // https://alpha4.starknet.io/feeder_gateway/get_full_contract?contractAddress=0400D86342F474F14AAE562587F30855E127AD661F31793C49414228B54516EC
    pub const CAIRO_0_8_NEW_ATTRIBUTES: &[u8] =
        bytes_fixture!("contracts/cairo-0.8-new-attributes.json.zst");
    // Contract whose class triggered a deserialization issue because of the new `compiler_version` property.
    // https://external.integration.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x444453070729bf2db6a1f36541483c2952674e5de4bd05fcf538726b286bfa2
    pub const CAIRO_0_10_COMPILER_VERSION: &[u8] =
        bytes_fixture!("contracts/cairo-0.10-compiler-version.json.zst");
    // Contracts whose class contains `compiler_version` property as well as `cairo_type` with tuple values.
    // These tuple values require a space to be injected in order to achieve the correct hash.
    // https://external.integration.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x06f17fb7a052f3d18c1911c9d9c2fb0032bbe1ea57c58b0baca85bda9f3698be
    pub const CAIRO_0_10_TUPLES_INTEGRATION: &[u8] =
        bytes_fixture!("contracts/cairo-0.10-tuples-integration.json.zst");
    // https://alpha4.starknet.io/feeder_gateway/get_full_contract?blockNumber=latest&contractAddress=0x0424e799d610433168a31aab44c0d3e38b45d97387b45de80089f56c184fa315
    pub const CAIRO_0_10_TUPLES_GOERLI: &[u8] =
        bytes_fixture!("contracts/cairo-0.10-tuples-goerli.json.zst");
    // https://external.integration.starknet.io/feeder_gateway/get_class_by_hash?classHash=0x4e70b19333ae94bd958625f7b61ce9eec631653597e68645e13780061b2136c
    pub const CAIRO_0_11_SIERRA: &[u8] = bytes_fixture!("contracts/sierra-0.11.json.zst");
    // https://github.com/starkware-libs/cairo/blob/v1.0.0-alpha.5/crates/cairo-lang-starknet/test_data/test_contract.json, but slightly
    // modified: "abi" has been converted to a string and debug info is removed
    pub const CAIRO_1_0_0_ALPHA5_SIERRA: &[u8] =
        bytes_fixture!("contracts/sierra-1.0.0.alpha5-starknet-format.json.zst");
    // https://external.integration.starknet.io/feeder_gateway/get_class_by_hash?classHash=0x4d7d2ddf396736d7cdba26e178e30e3388d488984a94e03bc4af4841e222920
    pub const CAIRO_1_0_0_ALPHA6_SIERRA: &[u8] =
        bytes_fixture!("contracts/sierra-1.0.0.alpha6.json.zst");
    // https://external.integration.starknet.io/feeder_gateway/get_class_by_hash?classHash=0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311
    pub const CAIRO_0_11_WITH_DECIMAL_ENTRY_POINT_OFFSET: &[u8] =
        bytes_fixture!("contracts/cairo-0.11.0-decimal-entry-point-offset.json.zst");

    // A Sierra class with the program compression introduced in v0.11.1.
    // https://external.integration.starknet.io/feeder_gateway/get_class_by_hash?classHash=0x05bb6c878494878bda6c2f0d7605f66559f9ffd6ae69ff529f8ca5f7a587a2bb
    pub const CAIRO_1_0_0_RC0_SIERRA: &[u8] = bytes_fixture!("contracts/sierra-1.0.0.rc0.json.zst");
}

pub mod testnet {
    use pathfinder_common::{
        felt, CallParam, ClassHash, ContractAddress, EntryPoint, StarknetBlockHash,
        StarknetBlockNumber, StarknetTransactionHash, StorageAddress,
    };
    use stark_hash::Felt;
    use starknet_gateway_types::request::{BlockHashOrTag, BlockNumberOrTag};

    pub const GENESIS_BLOCK_NUMBER: BlockNumberOrTag =
        BlockNumberOrTag::Number(StarknetBlockNumber::GENESIS);
    pub const INVALID_BLOCK_NUMBER: BlockNumberOrTag =
        BlockNumberOrTag::Number(StarknetBlockNumber::MAX);
    pub const GENESIS_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash(felt!(
        "07d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"
    )));
    pub const INVALID_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash(felt!(
        "06d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"
    )));
    pub const PRE_DEPLOY_CONTRACT_BLOCK_HASH: BlockHashOrTag =
        BlockHashOrTag::Hash(StarknetBlockHash(felt!(
            "05ef884a311df4339c8df791ce19bf305d7cf299416666b167bc56dd2d1f435f"
        )));
    pub const INVOKE_CONTRACT_BLOCK_HASH: BlockHashOrTag = BlockHashOrTag::Hash(StarknetBlockHash(
        felt!("0x3871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"),
    ));
    pub const VALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash(felt!(
        "0493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24"
    ));
    pub const INVALID_TX_HASH: StarknetTransactionHash = StarknetTransactionHash(felt!(
        "0393d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24"
    ));
    pub const VALID_CONTRACT_ADDR: ContractAddress = ContractAddress::new_or_panic(felt!(
        "06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"
    ));
    pub const INVALID_CONTRACT_ADDR: ContractAddress = ContractAddress::new_or_panic(felt!(
        "05fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"
    ));
    pub const VALID_ENTRY_POINT: EntryPoint = EntryPoint(felt!(
        "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
    ));
    pub const INVALID_ENTRY_POINT: EntryPoint = EntryPoint(Felt::ZERO);
    pub const VALID_KEY: StorageAddress = StorageAddress::new_or_panic(felt!(
        "0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091"
    ));
    pub const VALID_KEY_DEC: &str =
        "916907772491729262376534102982219947830828984996257231353398618781993312401";
    pub const VALID_CALL_DATA: [CallParam; 1] = [CallParam(felt!("0x4d2"))];
    /// Class hash for VALID_CONTRACT_ADDR
    pub const VALID_CLASS_HASH: ClassHash = ClassHash(felt!(
        "021a7f43387573b68666669a0ed764252ce5367708e696e31967764a90b429c2"
    ));
    pub const INVALID_CLASS_HASH: ClassHash = ClassHash(felt!(
        "031a7f43387573b68666669a0ed764252ce5367708e696e31967764a90b429c2"
    ));
}
