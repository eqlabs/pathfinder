use crate::{
    cairo::ext_py::{
        types::{FunctionInvocation, TransactionSimulation, TransactionTrace},
        CallFailure, GasPriceSource,
    },
    context::RpcContext,
    error::RpcError,
    v02::{
        method::estimate_fee::base_block_and_pending_for_call,
        types::request::BroadcastedTransaction,
    },
};

use anyhow::anyhow;
use pathfinder_common::BlockId;
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionResult, SimulateTransactionError> {
    let handle = context.call_handle.as_ref().ok_or_else(|| {
        SimulateTransactionError::Internal(anyhow!("Illegal state: missing call_handle"))
    })?;

    let gas_price = if matches!(input.block_id, BlockId::Pending | BlockId::Latest) {
        let gas_price = match context.eth_gas_price.as_ref() {
            Some(cached) => cached.get().await,
            None => None,
        };

        let gas_price =
            gas_price.ok_or_else(|| anyhow::anyhow!("Current eth_gasPrice is unavailable"))?;

        GasPriceSource::Current(gas_price)
    } else {
        GasPriceSource::PastBlock
    };

    let (at_block, pending_timestamp, pending_update) =
        base_block_and_pending_for_call(input.block_id, &context.pending_data)
            .await
            .map_err(|_| SimulateTransactionError::BlockNotFound)?;

    let skip_execute = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipExecute);
    let skip_validate = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipValidate);
    let txs = handle
        .simulate_transaction(
            at_block,
            gas_price,
            pending_update,
            pending_timestamp,
            &input.transactions,
            (skip_execute, skip_validate),
        )
        .await
        .map_err(|e| match e {
            CallFailure::NoSuchBlock => SimulateTransactionError::BlockNotFound,
            CallFailure::NoSuchContract => SimulateTransactionError::ContractNotFound,
            _ => SimulateTransactionError::ContractError,
        })?;

    let txs: Result<Vec<dto::SimulatedTransaction>, SimulateTransactionError> =
        txs.into_iter().map(map_tx).collect();
    Ok(SimulateTransactionResult(txs?))
}

fn map_tx(
    tx: TransactionSimulation,
) -> Result<dto::SimulatedTransaction, SimulateTransactionError> {
    Ok(dto::SimulatedTransaction {
        fee_estimation: Some(tx.fee_estimation),
        transaction_trace: Some(map_trace(tx.trace)?),
    })
}

fn map_function_invocation(mut fi: FunctionInvocation) -> dto::FunctionInvocation {
    dto::FunctionInvocation {
        call_type: fi.call_type,
        caller_address: fi.caller_address,
        calls: fi
            .internal_calls
            .take()
            .map(|calls| calls.into_iter().map(map_function_invocation).collect()),
        code_address: fi.code_address,
        entry_point_type: fi.entry_point_type,
        events: fi.events,
        messages: fi.messages,
        function_call: dto::FunctionCall {
            calldata: fi.calldata,
            contract_address: fi.contract_address,
            entry_point_selector: fi.selector,
        },
        result: fi.result,
    }
}

fn map_trace(
    mut trace: TransactionTrace,
) -> Result<dto::TransactionTrace, SimulateTransactionError> {
    let invocations = (
        trace.validate_invocation.take(),
        trace.function_invocation.take(),
        trace.fee_transfer_invocation.take(),
    );
    match invocations {
        (Some(val), Some(fun), fee)
            if fun.entry_point_type == Some(dto::EntryPointType::Constructor) =>
        {
            Ok(dto::TransactionTrace::DeployAccount(
                dto::DeployAccountTxnTrace {
                    fee_transfer_invocation: fee.map(map_function_invocation),
                    validate_invocation: Some(map_function_invocation(val)),
                    constructor_invocation: Some(map_function_invocation(fun)),
                },
            ))
        }
        (Some(val), Some(fun), fee)
            if fun.entry_point_type == Some(dto::EntryPointType::External) =>
        {
            Ok(dto::TransactionTrace::Invoke(dto::InvokeTxnTrace {
                fee_transfer_invocation: fee.map(map_function_invocation),
                validate_invocation: Some(map_function_invocation(val)),
                execute_invocation: Some(map_function_invocation(fun)),
            }))
        }
        (Some(val), _, fee) => Ok(dto::TransactionTrace::Declare(dto::DeclareTxnTrace {
            fee_transfer_invocation: fee.map(map_function_invocation),
            validate_invocation: Some(map_function_invocation(val)),
        })),
        (_, Some(fun), _) => Ok(dto::TransactionTrace::L1Handler(dto::L1HandlerTxnTrace {
            function_invocation: Some(map_function_invocation(fun)),
        })),
        _ => Err(SimulateTransactionError::Internal(anyhow!(
            "Unmatched transaction trace: '{trace:?}'"
        ))),
    }
}

#[derive(Deserialize, Debug)]
pub struct SimulateTrasactionInput {
    block_id: BlockId,
    transactions: Vec<BroadcastedTransaction>,
    simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct SimulateTransactionResult(pub Vec<dto::SimulatedTransaction>);

#[derive(Debug)]
pub enum SimulateTransactionError {
    BlockNotFound,
    ContractNotFound,
    ContractError,
    Internal(anyhow::Error),
}

impl From<SimulateTransactionError> for RpcError {
    fn from(value: SimulateTransactionError) -> Self {
        match value {
            SimulateTransactionError::BlockNotFound => RpcError::BlockNotFound,
            SimulateTransactionError::ContractNotFound => RpcError::ContractNotFound,
            SimulateTransactionError::ContractError => RpcError::ContractError,
            SimulateTransactionError::Internal(e) => RpcError::Internal(e),
        }
    }
}

impl From<anyhow::Error> for SimulateTransactionError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err)
    }
}

pub mod dto {
    use crate::v02::types::reply::FeeEstimate;

    use super::*;

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Signature(pub Vec<Felt>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Address(pub Felt);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct FunctionCall {
        pub calldata: Vec<Felt>,
        pub contract_address: Address,
        pub entry_point_selector: Felt,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum CallType {
        #[serde(rename = "CALL")]
        Call,
        #[serde(rename = "LIBRARY_CALL")]
        LibraryCall,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum EntryPointType {
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct FunctionInvocation {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub call_type: Option<CallType>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub caller_address: Option<Felt>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub calls: Option<Vec<FunctionInvocation>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code_address: Option<Felt>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub events: Option<Vec<Event>>,
        #[serde(flatten)]
        pub function_call: FunctionCall,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub messages: Option<Vec<MsgToL1>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub result: Option<Vec<Felt>>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct MsgToL1 {
        pub payload: Vec<Felt>,
        pub to_address: Felt,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct Event {
        #[serde(flatten)]
        pub event_content: EventContent,
        pub from_address: Address,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct EventContent {
        pub data: Vec<Felt>,
        pub keys: Vec<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    #[serde(untagged)]
    pub enum TransactionTrace {
        Declare(DeclareTxnTrace),
        DeployAccount(DeployAccountTxnTrace),
        Invoke(InvokeTxnTrace),
        L1Handler(L1HandlerTxnTrace),
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct DeclareTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct DeployAccountTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub constructor_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub execute_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct L1HandlerTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub function_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub struct SimulatedTransaction {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_estimation: Option<FeeEstimate>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transaction_trace: Option<TransactionTrace>,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pathfinder_common::{felt, Chain};
    use pathfinder_storage::{JournalMode, Storage};

    use crate::v02::types::reply::FeeEstimate;

    use super::*;

    mod tempdir {
        use std::path::PathBuf;

        pub(crate) fn new(path: PathBuf) -> TempDir {
            if !path.exists() {
                let _ = std::fs::create_dir_all(&path);
            }
            TempDir::new(path)
        }

        pub(crate) struct TempDir {
            path: PathBuf,
        }

        impl TempDir {
            pub(crate) fn new(path: PathBuf) -> Self {
                Self { path }
            }

            pub(crate) fn file(&self, name: &str) -> PathBuf {
                let mut buf = self.path.to_path_buf();
                buf.push(name);
                buf
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                if self.path.exists() && self.path.is_dir() {
                    let _ = std::fs::remove_dir_all(&self.path);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_simulate_transaction() {
        let mut db_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        db_path.push("fixtures/simulate-transaction-test-tempdir");

        let temp_dir = tempdir::new(db_path);
        let db_path = temp_dir.file("db.sqlite");

        let storage = Storage::migrate(db_path, JournalMode::WAL).expect("storage");

        {
            let mut db = storage.connection().expect("db connection");
            let tx = db.transaction().expect("tx");
            tx.execute(
                "insert into class_definitions (hash, definition) values (?, ?)",
                [
                    hex::decode(CLASS_HASH).expect("class hash"),
                    hex::decode(CLASS_DEFINITION).expect("class def"),
                ],
            )
            .expect("insert class");
            tx.execute("insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address) values (?, 1, 1, ?, x'01', ?)", [
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
            ]).expect("insert block");
            tx.commit().expect("commit");
        }

        let (call_handle, _join_handle) = crate::cairo::ext_py::start(
            storage.path().into(),
            std::num::NonZeroUsize::try_from(1).unwrap(),
            futures::future::pending(),
            Chain::Testnet,
        )
        .await
        .unwrap();

        let rpc = RpcContext::for_tests()
            .with_storage(storage)
            .with_call_handling(call_handle);

        let input_json = r#"{
            "block_id": {"block_number": 1},
            "transactions": [
                {
                    "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                    "max_fee": "0x0",
                    "signature": [
                        "0x296ab4b0b7cb0c6929c4fb1e04b782511dffb049f72a90efe5d53f0515eab88",
                        "0x4e80d8bb98a9baf47f6f0459c2329a5401538576e76436acaf5f56c573c7d77"
                    ],
                    "class_hash": "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
                    "nonce": "0x0",
                    "version": "0x100000000000000000000000000000001",
                    "constructor_calldata": [
                        "0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
                    ],
                    "type": "DEPLOY_ACCOUNT"
                }
            ],
            "simulation_flags": []
        }"#;
        let input: SimulateTrasactionInput = serde_json::from_str(input_json).expect("input");

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            use ethers::types::H256;

            vec![
            SimulatedTransaction {
                fee_estimation: Some(
                    FeeEstimate {
                        gas_consumed: H256::from_low_u64_be(0x010e3),
                        gas_price: H256::from_low_u64_be(0x01),
                        overall_fee: H256::from_low_u64_be(0x010e3),
                    }
                ),
                transaction_trace: Some(
                    TransactionTrace::DeployAccount(
                        DeployAccountTxnTrace {
                            constructor_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: Some(felt!("0x0")),
                                    calls: Some(vec![]),
                                    code_address: Some(felt!("0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513")),
                                    entry_point_type: Some(EntryPointType::Constructor),
                                    events: Some(vec![]),
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            felt!("0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D"),
                                        ],
                                        contract_address: Address(felt!("0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415")),
                                        entry_point_selector: felt!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"),
                                    },
                                    messages: Some(vec![]),
                                    result: Some(vec![]),
                                },
                            ),
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: Some(CallType::Call),
                                    caller_address: Some(felt!("0x0")),
                                    calls: Some(vec![]),
                                    code_address: Some(felt!("0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513")),
                                    entry_point_type: Some(EntryPointType::External),
                                    events: Some(vec![]),
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            felt!("0x02B63CAD399DD78EFBC9938631E74079CBF19C9C08828E820E7606F46B947513"),
                                            felt!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971"),
                                            felt!("0x063C056DA088A767A6685EA0126F447681B5BCEFF5629789B70738BC26B5469D"),
                                        ],
                                        contract_address: Address(felt!("0x0332141F07B2081E840CD12F62FB161606A24D1D81D54549CD5FB2ED419DB415")),
                                        entry_point_selector: felt!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895"),
                                    },
                                    messages: Some(vec![]),
                                    result: Some(vec![]),
                                },
                            ),
                            fee_transfer_invocation: None,
                        },
                    ),
                ),
            }]
        };

        let result = simulate_transaction(rpc, input).await.expect("result");
        assert_eq!(result.0, expected);
    }

    const CLASS_HASH: &str = "02b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513";

    const CLASS_DEFINITION: &str = "28b52ffda0918a0100352d013a01552c33c0668a881b70e2ea6854bd15835ad5cb7577b049bd13c48060e3141e082c04b0ca44494999037514dee20adc24088220088e07f702a802d0024d997bfdbbe6165bef8bb17fd5f6babe5cfffa9600030161c0b6f532776ddc9aad5fed9bbac5dcf9b66fe7bc96f999fb36e7da3d5bcdfeeebbd9abf7ea3af62bc104b2e0d1c041e4e198405518241c5042394152d3a3824f83634e09e113e5c49bb3a9f41449f1915372d024245495297ad84a78104a032aa83225e594051c4088a38a1e6962a09c7e8a8090a6240b0bc6d2b8b090f3a9a89e05900792094422f228c001495233e79c73ce39d9b3a41c73eb652a4939f69b73ad4bbf7594602419262e8da5b12c2c8dc63e29394d8faa602e9c879213e69c7356c888b173f96c4d560f55c1787c9292138f922a0a2545bccafa2be19be6c5042992d2b427331f68227a26335564f5aa09bde871188baa7952b29acf84a42626468f991c4a5672a2d992aa963392a629a9555e361f889207602812e530cebc955b859aab15f299a0ec40723217502451548f02bdca0292a9a488a92839e7831204bd0b2981810fd45426a682de64e694548c8fa9e0a3aa486a7517123451cc47c1ccf9a07d6fea415046757ef181de845681de84c8832122c2141001318083c4133d8e8ccc01044b6359a8246580aa5452d24b55d3bc98d5031f68a23820d0c7cc09eae18051c589c0a82a535591988a47bd88929585644090aa474950ba8713c3c8aa02a58564184955aa174d3c12137aaa8a237a20394df2004c2427c97151516f6222f5505410110e13868704c443326112702800227130abe85533922a19494840240d0d0f06c2818183246249cfa4e404c6d290d2612c1e05c19c555491207cfe5450e561be077a4c24512812743824f52a24502f929eea454f351750ccd7e0e251d40356a86a329606e5450c04559c0a0c04cd91849857bd08410f2e25555042723296460546054987315d548c443d0f3296862e0b8c4a4ec791a4aaa1480a6369ac6581210ff04c087a0c0e86899e47611806054a3ece5345323e8ca51181f1668452029414909113d1a3184b8311c949c928270684658131a3a7829e4ac3581a105489960586e4440f33516964645058161894474d48d4c4a010ae1deb6f471400e1c02430f165cbb9e3e6dadab5f5d7b96ddeddd42d0304e4010120124d951bbb5dccf4b557dfedaf75cbb5296b77cb2db35e8c759bb35f6d6dcb79add55edbf5b69740d877fddf9fddb77f6ff6e5c61a33ee6f750e1e1e1309c883c344597d35ebb75eabdaecde8de9baa66dad5df0f0008231802122b2809940185c4809919c00a91e0aa4ad77ebbd5bdbe96be385801c0061260e0f1004abed8bb781b96daccb1b5baceccfbccf58db75dfac395e8db9ff625f8ddfb1365f5dcfbd96ed33b7cd8d29f772fe6c97814c1e0c201148832e86519754535616901403043d6eabfdba656df12f65f65ffddcde24111306480422c14c181e920944040313893c181a469d99330f9089030361f090444c2498041e0fae2db7cf1a2fd5f5fdeab8b57db9555e4dd99be3f77e5f75f74c374103c48388050cafeb756bd9f2d58c9dae4b2091068847036623bfceddcbb7d939c4808803201c7ad731d3d5586bdd65e766cfcedc7db5366fbfccfd3fb3d609c4830806860753808888036fadb93b6b7fd79c1b330d241e0d1888e411618034c0c9e19ef3002f02582240f8a5d138f04de7f20b869213242829c8441263c1cca7a94ca84281b279200725a1679a881e34bde57091841cd35bee8b49828cac448fa43caa0048cd6a76d3546044681c58090c2c025826c740351f84c0982a1235c14c448f04667a0c0a124692928ea4de6b1e6bff8cb9afd5cd73a7ce4691d5d37697062b2f0bec1cab21d93cc8274982a8ca420f4a914992220c3d8a6a42d74e444f8c6f62a48899cc8c9454c144552429aa022ba85289cf9414135f6501289b6bcbd779af7373ceab6e9b2e3b755fd66c356be624900649c4eb5ad69cdd9997e3d5db7429af5ddade6d39def6eefede58d36e6d7d5fd93d638c7d0bc0ca98b6c61abf6e5bdc7a7db72db7b8db5f597b768b750b76c3cff1fa66cbf8d74be6b05e9041b6acb97154327d2d2e6e2baa42e7698bccda8c5b5ce838dfaa4b3ace374d792dd4719cdf65a10c080b8ca5b13496c6d2581a4b8392132f7a146675579b853ed4e4d8752883895021c2daf7c6ef18f35d4d1babffd276dcdc6c6bf13b3b66f4ee3c309746c3d178ee2e8d5e670c8aea2958140060813c38481c2c01580e2458087054681a15282c0b937a0922295a16a2849ee72c04380a28b034164a5a22050e340a142c1632460fe358962552c0c0a2a089d15b0e54d1b3349e01099ff92c0a1686a2929a4881032494679150f3aa072548520eca84dd666938a6db9a7bf68d3d7b776cb17bfb5a1a8cf828581a0a0cc4e851ac65eeeab160ad8b9c905c7419c0122dceb3eca2608914d845418225f255ae30e3b32c10101140c10025ab48329409acbc11627c923221e7a26089303d081794449114d52a7a281cba5494344d95b94c29c56559f8174a525452f49625ca66a9a4287a7059e64331591c4be458dd62b71a4c184040220d0e91c701100e8c0adb1c1fa642829c2ac2d2604c129c8c849a674ee9db0c255194ac2acd4355d57b3c306d02e1f08059dd575bcc7e5ff5b7b5e75fab3d73bfd829dbb5d82f67beefaa87aa90d54355c8eaa12a64f550155b3d54c57eaf66cdda2b8265e1dd337fc6cdce1673aef9f2f6eddf78ee5d1a1556f3f2c3488a587c28fccde85115b3345af55008f0d278280498e393128e4f822ede2455f3426223d2e42146b2df31634c5dd73756ff854c1c24087053a6dfed98baa6daf08048f4ff7bb1f3c6dcbe3ad7abb51b8b984848401e98060888c48318247cd024258c69fbeeb57eb975a9baf323c2c040181e110710c905f5a8e651c6f677f5b9977bc6cabe99395bb6163766b7feeeaebd3aebff2e7ff6d5cdac5701240fc9028788840402078bc98491c48392d54479d59494671231cd56202440095a50c977affacfccf6f7d7abb2c610c983c90382818344b3b62eef2e650d15222088302b64c49892baa81ee8695e5579e0ad9ee6b96becde6bce5387dff5636e5e7cf81cf864d3d8f9bf95cebbb9f66acc45c8d469a0c3bad539cbb13bb171ab4ec31e2b3fd72084b0697039f72d77f1b673c3eedc719665cb66af69a263bbfee337ff3442f6b8dd157e336770c1c8ccc9c5bfd0996c5c7b2d2e5f199d7237cddc6a228c4d753da71d8bf2c1c84bea8a2f9bdce61b5f749a079daeee06637bedf945a7bfcb693f6d6ee3e3b5fb8e6c22ef7272c5e510c2f5f52a65944d6c9a6e20db6ded98b5e6bca3722973b856bf668ecddebd0c5b8cb161df513eb96b9de5f8b6bb94ab3ff673d3db38feba1ffa73fddd6c1be750d98a31be74ec5cd334fc06ca26325e57b99af37eecff0f5d746db951c7d1765654b9cc7235caa07b0cdb791d9b74d69b375faffb45661d9b94cfcc9b74f89ac639d261ae8d7bb1b16c78c96d5d8e367cfc208bfd7445dfc8034202992400596e1d36fbefb964ef2ae332f3c7fa9a39eb3de774a97bbfb2dd3dc6eca8e334080f24130988080606858b869917541549b89ad790bb31b7aa7b6dbdc5ebd83d08217b2961e4d62c6373ad890e7f95a9f3eaa6e38b6c75df920e6bdd9e9b31cbb8d65a6ecf1e7bedef39289bad6ef449d9c0b878a5765b721763bcecdab7e31e741eebbae63ddee5c8c60b1feb869d32f68c7993517af39cf5de1d6712767b749e37aafa7677f56a0d4b07bd35cd7271dd39838ea31d9be840e89a666d4ef37a5565b7d5746f74d8bc43e85c830d6cd6b1aeed7dcaed3db96df5b5d15d86cf4cd9b1c31893ccadf6cbb971b6de31fe871042b6cc19bbb377d8fa7656d6dfef6cb15dfcced63bfbe69ac3e6b9e6de6190e93b5bccdf058a77a8f4b40ad4a8534a313203c0089000f3110000282c44994c4a8b9cc77a14000e151314110c0d0f0c0e0e0c09090909070b090a08050987c3216128140e88848121796c36e9e478006d0a19b1f8c66d8ff377368cfe7ad5d5d2a0feee70d21786d3b0435475448db1040cc9dd93356ef0ab578011db0985c68a1a19df875c5e20f56594748a38b89571537371f3a6c77abdf6fc5cd97ee4fdb1a65f87c9e71bad54a899955d2385a74de7fc7e3fd3d57b1dd55789183b61a0323e2abd46caa3c487c3a4f0dd49c30d22d5ed4bf38804dd8025cc69122e42f6dd71aabf1fed08300b69a832f40db1411149eedd27705e833ad8883c2dbadb5f22e2f3d18360de169cf6a2f305720d3ac0268c68814ca72f51666de859b13d8113034d7700b50eac9b6099298df085bb6d5284ca1be204d8f32bb50ad1e80e139271e1f075d84e0ca3c64b283448daad10795104cbc2e559d798bd1d7cd84fcc19b41902c6e2433fa5880289f15f07fb2defc5ce76316daedeac0684150868e98097106d4006e0687918cbf5b80dac2e5255a3d43549b9b09723b31a4527e1b2f67a4511e8de72791406d6fb804dad7db99b2004bb449e143e15d179f901b28410f287c00cb12180f9d93850f602a4aa6d8a9d6035c8a95f752a8148976eae7bdcb1affdbd49c1baa77d0926213a2905df9f3c0ecb7252a1d45ee1913f8d16f35995f7d0cab8fa8bcdf74173294058a5fcdd06efc01959eb296e7bd4a15500b18d3cd88bec0cc0fea0f29c8069172066a1159bb5b3643edd3ec6890dc43a1cc323c3b95776ca42234954c7d26ca1fb9880c6437664276f04e3565a251dfa9eb11d85b86eb371b0a04141933f902438ee8f3aedb48bae5141886b43dc03c7e4979fedf19c604b21a099b9dde1474848210fe8b774a48b1fd6811d54d4ae3615784545f8bfa48b49e8c316d03d2e11cc7a0bc8ced911a39fd5d8d1baf5a1f2cc6273d333669c3b6b53f81aaf9aeccce303e4a4a28abbf57fd58438561221fc735eeb65bf24e4c005b83e6ae6b8dfe20e206e3896bb499fb9774584c10ea456800c4c265c2c9883808a0d528ca89128f68c7fe1b81d4a420fa099d0023aa9071a470d9757845678a8d6da53951398d5a35938e1c528de0feed80df610517aa39d8ef8968f3b4116affb4d3850a5e7004eab3448ae0c22a0e78582f7262171420105ddca557c8ffe6dc5a4e445f1c4a8411839beb3e3853e725e9f160b4c3dd029ffa1b437574afdab8141456b3087158a0eb4d3c1ac5353ad9b1edef09bf0ecdc16301811b6902669e1ecd9087d099c865683c13535ef00c21be5446ad5a9c79352b67761972fbde959f22eb30afa881f78d7c59bb8d61ec483ac39f146453af1eef3945fdc15a9824fe081291c4394661118c670fb7732db3890803846a424ddfa4ea989955a43641fec003771d54a14881eaad2d0841333390c02b7165f23e0c051cc200253624e90a6066073c9afa317e071df8d13061839f2edc87858884eda7a6e2fa6fa4b00f762c14c5e003e596341a0af186e8f0d637f6eb91e7f9ba3a419751040282a4c39f0a02e232a05fc8d00404c73d148e926b6d15cb19e14a1cf717049207ca640164813a603b72ac37f382e9656b691cfa09e8560a9ae00908c1d3be121eda55249bf16c4fbd34e7853d4950876fe5e2a5f16ef8a8878d8eceea0cde8c228f3867b0b497dd56c45c5bdf80123dec8b36e9cf181af54b77bd9f6d54afe871462a24c8270d84ef404fdde6030db1479f3c80290bbd3515348a089ae38d98c91f5cabb3dae011b504e3633b3da0b2727e4f35241ea153ddd716ec2f05583e1bfd7c27a921c13d8ce6c5651958b69c29af05f9892df79c3371729fd3d4451f6004eecddf2c35b0958415f049c71f9b44e0fbaf9c953d217cb5054d4ac4ee7263f9b5f8331edc59a260651c492eee241f88191d581ebad857c0a6c8f030cfefe452460f07c6cd441c4c0be26379e9290e083e188e74d6ae8b8207e1e09f688919c34e0dd406de204074f8fbbb9f1eb0c6039cf20cd2d2c19e38854c44044c46cdd74cda32c24b79ad0cdf7c6af7a578e0b0384aee1370f034f8e917e2c3bc883adc34c9a8474c89c204c52bce0aa2a089c088199af8da9802703df10e11f06c7c9049c82f81fb2485a8265610d47e57d7814ca1f41d4421ca73f6cb3c19ee875f988708f0119512c7e2d6858145bebb0ca73006779be7256feaf43e310a5dfbe962a79871ccde3ac2c1eab8fb27ffd7d16fd4ed0fa3209d25bd76f7509813ca30cf34d58e8e5ad7684276fc2ec285f0bd51ccbc5f7693570539e4dd572faeb1b6a2825ee96f8b93601f916df219da105026bdc04af0e3baa1e28a754b867ec7a275abc9612d3dfa04baeb91b2674d3068693b19de8480aef7a2a222bf9bfb147af91b62d34d150cb6ef073a9d7416146e7d0132c5f1a876601aacf0a8049011e88810c934b925de44c2bd4c1f3560db4189de4fdad70603a591a48ce3cfdd866288dccbcb71dc5d13c2eb74b66ca976b5fe394b4a90418358bec3fa3b088d15e3e753d04d169db11c48ed8df1cc7e9ae461a19c34b316307cb97a7fecfd1240d32f34099f9f01631b82e7aac4c6c03806def12de1900207d8668b37442ed8635e92254d6d3cc5edc652e9f35c6eb78eb3596e62ca6c6a3ce3b8ce00f52ae465945fab4f3dec6fb7a7e718c229843ad7243f80805895f93ad88a219daa4fda2a726eac8bd29176972316e76a73411466d510c13503a966cfad9a634103a1753e7100d5f2cc91606cf16a1f67d81c38a603977d07b2d4045a85a45c2f323864fc222440e25abf3be60365b1441b93e5ccbe923ba07244c0e48dd6b86568877bcfe537ebb241ed0310c20afdf4f258d84fedb415f96f1e1dc4e5256263157d76106894bbd4721ee432c180a89c22a11076f0e7245748ad3442b3606139850bc8640f7d748df30f92f76cb33848d71455d2b12d329443c1501777d27d245fcd170c48b4ee21decb20141071914114d78caba00f677fee6c3f8f40f53d9c35477e454172b4fc5e9da2ecc17ea72a8f5b97d47cf390f8cd2e8d1bc38e289f988aeba47cc845198ad0cac43ee70a01c72c54a08b4b37b30e3d2c0796f96e780b5c9d741f3932824a06ad3c7bd2d8b214fa91d184d1511bc45e8a2f6c4552201b26b3a6f3f519a7ade1ccca22f7f9f44bd700a84eb56d842bf3754c965bd264238cde178332796f26604d966ce37c013e2d497212bf6972741ee4725dcdca0954fb5d5a19b900514c97fa94430ab845634047e0143b68c233149e6fa85110a07fbf28ea4602fbd7e55ae09418c175136c68a492966cf1231ff81614c200669d5d185a873f474124ae8052d2b1d4f026e8edb9dbca4ec9448047f15b8f989d63caae417a71ea244623c0426419ad79d4bc474c5a54bc4c4cd799258e002b1d37939c222707aebd35d47412d94537a48ade06888ab27adec24b66c86d1498af10ec8cac2c48b8d8012ab91252d20d9eb93f392a7c1522411a446de6f3a363f28916b2ef4799fa858a6483a2f7aa9540b3c1bf1ac89b06b0752640ae112a7b72b6d31789d56b454c4383cbe44ba011099f40a61059c551b6c74ebbf864a58b8f99bd240219fb3879c505030c450840c41ae5b878748c9d8364e985893ce0223c5461c0f905ab37505a9655f134986166a944be599af9ae9082046a2b908aa5bb010a6ffd7f24d1c4cc1c658145a4b184b48ac3a42154a4b627709e042d12fcba9be9796fd8249bd880c2bd260545a2994ca00c417e95a79ffe4e1eb0f544c310cbd4a2a6f11dd37245df2d136a40c7cb9da8491dd6494a930aa78f37564549e7d1095c2d00e5af2aa5f5a49a30b80d4b972af6b048a9af74644f3e73ed48f48a73b8fbcdbd32323b1d81f45cf4163d9c7c9b6a9e1e9b4586a3526edf661e5d03caa883ea4b9396f92d0d4a4832a04462f953b0a7b3fcd0684af15f2eafc324bda91401ce6108e52a698d50038fc20dfe7317f3b1d6bcd41822246eb716c1c6b25a73f42ac308436977a70ea0e318c4854f5249bce07772b48040dbd856d52d19f5b6cfc63a1088edd65d38317a5c56c837e563944e8ebe94123196cfc0b05d081c055bed3c0ec823421038dcf3fb0ed6a57ef02cae14389df0087e39cc69d45b8a24131f18a7b0d38f97096c66d0bdef59dcb957a4f381c26a11fa8ec853b1b40c5b976fba1030a1042809bb042e5a3378b6579ed75472566c59718fd309736ed3d346283fe21ba338c412d442ad1a1eee64090853d87883cddd121a231ba7ec9edda372d870f2a6051ea13032db7af14f64eae5a9ad5b62a72b6c0b6601a2dfd81fb2984591a640adb51cb1696ebea048d34ceacfcbb85cc81a94ae0da6bc49eda4299a18cec29fa8633ce4ed62c22425084cc94c2012a37fc78048a276e5b48fed86a18092fd47c7aaef48c432655376e6e2a62d9377405f916b2ad89febb2533c26cd7ae856587fb96f8865b616c3a0951bea9c4b0145ac107b6264f204fd592773ac0eba4ecba2977bc6975a56d6f340c0c56fb08d81f4dbf528360df11aad85db2734af723e082a927817745be8cc54e6d4cf78e095e807a6778fbbafc2995918ab8a988e4bf0255ad72ba36f7a50355452cf3955cd2f5a954ae45cff05024cd3f3e7c31ed184ab8ea65a04deb6c63f5d43e016e54bc166a3c097a7299b939e779b93d9cc4bd7b1f2a74c49f167fec1bfa8cf22dd5ba1968ea9a75d49daf62dd19a6fd54171d3ef8a0fc0d9e1c42200daca49c8baf48194ab73ce8919e33e62ac74730988c6d1f0571dc3861c30576be164d5209cb83b14e7cce701ffcc74fcc1377d2d0a29f84d6243fc71318a1e8a0ffce7f3b36bd12f0ce7d9a227dc6d19c9526497c640f46f0a5c6a8c78e72f802a78ab2980558438c16199b3562cebc6f0b35aacd20e98ae05a4184c6553385de4a4c26b0bcac520269bfdcf21b9dfff502f7fdf6379f4e36bc299c1b6623de10aa7753b5e78b2b854455e409d0ea4acf29cb418cf280091cd3ff5ad928437fe2d37f54900597a000808d058c0ade5872204db16d76c561bb22a39f02f6bb72d8bac5690cb957b61fd8ff8fa3da1bc65e218723a3c6c47bcb372a036baf248fc7950347e6e360a6634b8f0d2a48c6383fac615b63905182f879d0510a5b7bf6c91a5aa4125e1ed3dc7613ec3d9fd03254ea4c52f75bdb990f89961745bec39eabe67cbd045bd1a5021a305e2168d7d25e4df671e2f7ac4194df00506c41ba9de874181af5531dfd4cc0d395b64f95490f1a35f493505cb26ff012f50496bae18ec5dad8bff6bdd5257b86c22db0f313bb4368da75255a885da2d1546b02da6213f9d1d1a7f837740551fa7086c8765b0088c2b196ae61bd5117662ff685b486d156b12b2285dc25ecd79850813b8a2fbe470b6e9c1e4d48abb761f507043cba125f718782c2fb4db090df03c51d6dc5785f284bcbc624135639d14047692e6d7f9c7f239fc124fa0c5635d45c37254fedca8cb61b8eddf6c80d6e4c4db18282f885179cdbcd8cd75a2b0f904eb3d83a20640ad8b25badf703b1e44866adaa73d9c4a3778439ac045e975ba618e08c5b9fa3f8cad0b73abd2bdaa5b98f3041dede123fc8c41db668c979b27fba370dfa8bf073f4889558c8db8825788d879e1dfb40a26a47be2866610c269a2d1466109ea7f20d55d1708762a7568626ab34304f88a487c691ea07c7a009479af0acc149efcb04e486cc4e90e03cf644219edcf64dc63b5615884f5bf36a2de7056ce02eaaff90bc2b4d79a50be461db3cfcedc5214b518e830fec0437f51e246fff186112631579adc774c09e14f40f6b64d74748c6376753d57a4a15a05683735d90d460f15860cc1d121acfb65238e1757ab64b8b00b7b32eb8cf5f271624c9b56823be918655658c2582f88f453020b3a966a7b9575ba665abd042679f376b8cfc24e9ac413047ba2664925ba2438e198207d9530c645b37fe2250010e18140fd396f9e27a19c02dfb5e3b6b9b4e175d35a794bc6d95f4d618970daf6c4b5c77b8d17173e7f74c93d9738445b04c1ab9e456ee6e4729c836785288a046e115238f2720d09312c4e9412e924f59256062b4a1c6020cb6171c1b520289bcd5acc85277194bbad4ccfc7b7e374900ad5672a5695b922deb8fd7a45aee363fd9cfcfc24c4d51f63fb05401f51575e31ff3be719126a3c69c9c88985ed0b446b2b475227d30983759064241c84d0966ff593ebf2a2141e86625899f0bbce953bd8a49871c9732d122c9dbd4395373cfcc2b75e24ef7532f7aba2631ee5993b4de94497279ca9de25a5572d2d93843c65807d6a9335e2ea801ef81a281ed91c28a1f9c5982c2325dfed3564ae5556be86d6896215dba138d15b62cd1156348c85080c7812fdc0c5c78e12a0a8ef9e391950c9953ccdcb2722e44bf2b1587026d3de8b5a5ab2f0e115cbb56b6d2cd84025f0ba68e0f90c85580c4d0890cc19486ec18fac4b003ea84b9e493718d6bff42e3146315a1de7231582125f4cab6cf49c277eb1907e508c93db4d0edf306cffd2a891adab3b9acd4150b3d574423e2072516f7d304ec64e4cba2a3c31d0e80c9bcc89c14d8de201e04e2d9a22eac5f0bcd39e0859cc210c3ecd92061f991913e0b516d09cb1deb4c28382caea369324850584861d0e706b211f22de82b00308e84cb07aaec6f84f56eb26843365034c343b7c63538b7c9f918492d7b4531fd5ba619ffbec175fdcb077a07c47132f1c37a1684c226e3e85820b2e663995e8100fe241b3e02a3e492ea76ea0c1c38000f221d22cb0b813e3743d59777d79c3a255cd58ddfee0594af3aad877d03a2146955d9f685a67b49d7d238c4d8b866e2fd9b2a859e997a80fdd3781f1556a86e3f82048e5e1eb0b852cd068b15959b80af9cd691bb4a930590fe06fa50194ee2a11bb5c1208cedb6081baac5b6f3242d333369066badc746cbe8c1f4145529b630b340d4ad14e7290a4506a93a62cfbae11b5925f4112ccc11a3661bb59a28dec26bb7acbf25a46ed5ebf26a292f0fc0dbf68322fa1fce8eaaebcd4bdcd601822cc018d49168b46e111d055064b3748b2bb002f38d3ae09a3cb24704366b35771bd06218c1cfd0d369afc93dad679d8af090c3e20f663956ee522a7badd26d53937af3d89aba4301fd8752b610bab9416d16d5383e68ab375945bf198eed42f2450cf6b58be1193cac8848a90bbf814ba760656cf0ed71bb47cefed86b679229d016b4406ce0fa468df6574afcfdb9c711ca7deb9aecc0bd1051a7c2427ba7f9a8a4747045eac79aea5baa0695615872c6a91dbc5822b3ee9daa5cb4d521e32ad3d85b09ba28ae39ffe46afc51eaef2ad1b043f763aae01b2712872692b0a8a0f8fec9d00ad6c884582d37b065daa5aff49fe4c99b4a10d6e3335eac87a2fc27a583699a3b4df200dd37a1bd9f96b55873d1f0fac756c600fff610d5b4996cc1dbfe37413febc6d0de1f313bb4bd03ad75ae7cdb8bde88871a02c8b82cfe838db62bf95b7fc9e2a401f6f1ae5149976c7ed11ca867951988c13287869c5d2b599947d2f8facf899291e2567d57bedc73fef03afd18f1db185a68db7bf67d09903111b8d111132af34c1d66148daa3bfc546dd03b4f906c2443c5fd9772fc3be5f3d10fb593dad660945f9aff14edcd2fda59006043f57a22af6d8700d43f600784df3f0157fd8abb96b9fed6000a9a32f680f30c74e21a81d811866b2a67f80da848e720533b00fdd7e3606e8037bd06906359df22facaa70d9a64c60caf043e2a620e15e3c6cff340c3d3daeed54c50288e93046deb01a6e57c1792cd1f6cf4f9d8a4b055ec627b2d9f336a3e3af439fbd708a934d933e8ef44e797bf279b5ba95b72cd0cacb95211298e748e69b93849cc564d9ddf2ef10567a638732eacee3eb960d4760f21adf09bf5088a11ef4dffce3a3dd31c4fcaa3169af889bca315db499173d6118ce8a892d115501d94702e0597ea80ce792907693544bf728970883b84c4b895558c090d94f6c84ad8fd5a8c2dcf2823b0b28cfcfb82feeb38514c14726e250b367efa1217d84ea63b51f171ec707cae8317675f3dd32ce99a91e2e6be526cab89269101ed97ed61f15243e47afab5bd72fdc6dc88d9127769e6fc9781e72b942729f45cbab57e5cfda8e0213663f0526a2088d8441728aa26b3941471b5ab23c90c294c38966d62568ff12e2a66ced08916a224468dfde73693befe8a1fd0f1081b33491127ce0a551b7c57c9e56ee6e4b02d83c10fb3074867dc31438d580d23931c8203aefbad34220c12021c606ead50e048d5c9802aca267160babd2e041e40180f248d5e43e3615922d61a37f9597f23b81b0fdbd57cb82ce8f195d33631dfbab8d2d70f708f0978b089febd76a2368443b80781329377d70d6fdbe9a9a5fe55ca080bf54e3e05a5b235cc7a7aa91afe7f84aabb50bf37ce854e48ff61b86fd56dbee5e85f38dc18e25e9bc2c8f0e9c42e8cd69c188e5c2ce7d612de05f07118e5b766b8ce74afefc9c834e678621952fe5504b940793eeb580e654e3f7810136db6f533166708355e6eee313352e583aefc0f1b22d6660b969d9965317bf193cdc2da4d870d3385c85873f99f17d7bfa156bd7913d811da2368b427701ff7e4c1cb3d53eb9f51a54366811618df679bd97e1b52837bfaf1725ddde736fdd1173bab5c17d477d7cbb0c143e898f1072f75f72638a7f8c7298d71851f47c674dd8b91f4447cd174649814f57aa99c45dd961be3a52a1754806f58fb2d619a11f8e0d4bd4d07ac35fd248baff4dc259105472755cd5aebcf99ebd3f908dbe97ad2567329995b8c47e856e9a7f1e678520975e6d837d44c555907a159d837c8981af3a3002db05e8c8a8218007f43a8474f672fb280df312b8d6c6f128822f9f7b4b09201bddc72e0b09477e984ac0a0e3cd740cb79ff30e69de909920578b87ef4f672fbd3582ed245a2fcf0db7e7ff682e05c2a70d043dac94d290a2e2d5d10d5100707a13bc27ae27d141bcbd12c58619aa7329e9b4f2ee978cb3a0b8e026b0f7c813f01f081e250af9675eb801082fd7f360a2cff7d83b0bbdee109af67ce03d52924ca683ae97e171ca0cbfab9417b3afc488168e440321893b2fdf823e096fa0af07d9d3db22d94bee9219f9e9cb9643b323f6b9abf6963f7f42023662beeb42e376dad3bc9212660dbe9aa93f036b3b62fc90049b6407e2c0d88d12da15c0511b8576926c239b537e9678010f1cdf110aadeb4c5ae1e52410accd4b1a0086785f98ac52e6b8cee557588f59ce7dd61785e61ea6697376d5e16771bfef2cb7c6eebc99fbdd04d565bf626ec956b6eaeb3a3a901f63d673f8c4e286cb4e40e0dc65d092abc6156118c7b727ab58cf4e8946fdc7857a8290337af23e47046462d0cfa064e0f3b6feb70b334d4142100c82669430aab289734c3f288f023ab492a0f4f3b2f4d298a7e6ca3ed1ab241f348b3435ce1e0ba5a8dd90d34a96ef944803ddbbfc0e80fcbc0df104f03f703";
}
