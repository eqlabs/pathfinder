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
