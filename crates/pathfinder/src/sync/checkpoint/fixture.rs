use std::collections::{HashMap, HashSet};

use pathfinder_common::receipt::{
    BuiltinCounters,
    ExecutionResources,
    ExecutionStatus,
    L1Gas,
    L2ToL1Message,
    Receipt,
};
use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdate};
use pathfinder_common::transaction::{
    DeployTransactionV0,
    InvokeTransactionV0,
    Transaction,
    TransactionVariant,
};
use pathfinder_common::{
    block_commitment_signature_elem,
    block_hash,
    call_param,
    class_commitment,
    class_hash,
    constructor_param,
    contract_address,
    contract_address_salt,
    entry_point,
    event_commitment,
    felt,
    l2_to_l1_message_payload_elem,
    receipt_commitment,
    state_commitment,
    state_diff_commitment,
    storage_address,
    storage_commitment,
    storage_value,
    transaction_commitment,
    transaction_hash,
    BlockCommitmentSignature,
    BlockHeader,
    BlockNumber,
    BlockTimestamp,
    Fee,
    GasPrice,
    L1DataAvailabilityMode,
    SignedBlockHeader,
    StarknetVersion,
    StateUpdate,
    TransactionIndex,
};
use pathfinder_storage::fake::Block;

pub fn blocks() -> [Block; 2] {
    use ContractClassUpdate::*;
    use ExecutionStatus::*;
    use TransactionVariant::*;

    [
        Block {
            header: SignedBlockHeader {
                header: BlockHeader {
                    hash: block_hash!(
                        "0x047C3637B57C2B079B93C61539950C17E868A28F46CDEF28F88521067F21E943"
                    ),
                    parent_hash: block_hash!("0x0"),
                    number: BlockNumber::new_or_panic(0),
                    timestamp: BlockTimestamp::new_or_panic(1637069048),
                    eth_l1_gas_price: GasPrice(0),
                    strk_l1_gas_price: GasPrice(0),
                    eth_l1_data_gas_price: GasPrice(1),
                    strk_l1_data_gas_price: GasPrice(1),
                    sequencer_address: Default::default(),
                    starknet_version: StarknetVersion::new(0, 0, 0, 0),
                    class_commitment: class_commitment!("0x0"),
                    event_commitment: event_commitment!("0x0"),
                    state_commitment: state_commitment!(
                        "0x021870BA80540E7831FB21C591EE93481F5AE1BB71FF85A86DDD465BE4EDDEE6"
                    ),
                    storage_commitment: storage_commitment!(
                        "0x021870BA80540E7831FB21C591EE93481F5AE1BB71FF85A86DDD465BE4EDDEE6"
                    ),
                    transaction_commitment: transaction_commitment!("0x0"),
                    transaction_count: 18,
                    event_count: 0,
                    l1_da_mode: L1DataAvailabilityMode::Calldata,
                    receipt_commitment: receipt_commitment!("0x0200A173F6AECAB11A7166EFB0BF8F4362A8403CA32292695A37B322793F1302"),
                    state_diff_commitment: state_diff_commitment!("0x06C4A7559B57CADED12AD2275F78C4AC310FF54B2E233D25C9CF4891C251B450"),
                    state_diff_length: 25,
                },
                signature: BlockCommitmentSignature {
                    r: block_commitment_signature_elem!(
                        "0x0484A36B518E33198BFE7A29D82842AE092F9181120E1D49B926C651ADF315ED"
                    ),
                    s: block_commitment_signature_elem!(
                        "0x07E21090AB0C6C70FA2B73E17E6288DB298DBE191B04BFD1721436530E84861E"
                    ),
                },
            },
            transaction_data: vec![
                (
                    Transaction {
                        hash: transaction_hash!("0x00E0A2E45A80BB827967E096BCF58874F6C01C191E0A0530624CBA66A508AE75"),
                        variant: DeployV0(DeployTransactionV0 {
                                class_hash: class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                                contract_address: contract_address!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"),
                                contract_address_salt: contract_address_salt!("0x0546C86DC6E40A5E5492B782D8964E9A4274FF6ECB16D31EB09CEE45A3564015"),
                                constructor_calldata: vec![
                                    constructor_param!("0x06CF6C2F36D36B08E591E4489E92CA882BB67B9C39A3AFCCF011972A8DE467F0"),
                                    constructor_param!("0x07AB344D88124307C07B56F6C59C12F4543E9C96398727854A322DEA82C73240"),
                                ],
                            }),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 29,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x00E0A2E45A80BB827967E096BCF58874F6C01C191E0A0530624CBA66A508AE75"),
                        transaction_index: TransactionIndex::new_or_panic(
                            0,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x012C96AE3C050771689EB261C9BF78FAC2580708C7F1F3D69A9647D8BE59F1E1"),
                        variant: DeployV0(
                            DeployTransactionV0 {
                                class_hash: class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                                contract_address: contract_address!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"),
                                contract_address_salt: contract_address_salt!("0x0012AFA0F342ECE0468CA9810F0EA59F9C7204AF32D1B8B0D318C4F2FE1F384E"),
                                constructor_calldata: vec![
                                    constructor_param!("0x00CFC2E2866FD08BFB4AC73B70E0C136E326AE18FC797A2C090C8811C695577E"),
                                    constructor_param!("0x05F1DD5A5AEF88E0498EECA4E7B2EA0FA7110608C11531278742F0B5499AF4B3"),
                                ],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 29,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x012C96AE3C050771689EB261C9BF78FAC2580708C7F1F3D69A9647D8BE59F1E1"),
                        transaction_index: TransactionIndex::new_or_panic(
                            1,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x000CE54BBC5647E1C1EA4276C01A708523F740DB0FF5474C77734F73BEEC2624"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x000000000000000000000000C84DD7FD43A7DEFB5B7A15C4FBBE11CBBA6DB1BA"),
                                ],
                                sender_address: contract_address!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"),
                                entry_point_selector: entry_point!("0x012EAD94AE9D3F9D2BDB6B847CF255F1F398193A1F88884A0AE8E18F24A037B6"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 31,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![
                            L2ToL1Message {
                                from_address: contract_address!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"),
                                payload: vec![
                                    l2_to_l1_message_payload_elem!("0x000000000000000000000000000000000000000000000000000000000000000C"),
                                    l2_to_l1_message_payload_elem!("0x0000000000000000000000000000000000000000000000000000000000000022"),
                                ],
                                to_address: contract_address!("0x000000000000000000000000C84DD7FD43A7DEFB5B7A15C4FBBE11CBBA6DB1BA"),
                            },
                        ],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x000CE54BBC5647E1C1EA4276C01A708523F740DB0FF5474C77734F73BEEC2624"),
                        transaction_index: TransactionIndex::new_or_panic(
                            2,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x01C924916A84EF42A3D25D29C5D1085FE212DE04FEADC6E88D4C7A6E5B9039BF"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                                ],
                                sender_address: contract_address!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"),
                                entry_point_selector: entry_point!("0x0218F305395474A84A39307FA5297BE118FE17BF65E27AC5E2DE6617BAA44C64"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 238,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x01C924916A84EF42A3D25D29C5D1085FE212DE04FEADC6E88D4C7A6E5B9039BF"),
                        transaction_index: TransactionIndex::new_or_panic(
                            3,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x00A66C346E273CC49510EF2E1620A1A7922135CB86AB227B86E0AFD12243BD90"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x0007DBFEC95C10BBC2FD3F37A89AE6E027826134F955251D11C784A6B34FDF50"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000002"),
                                    call_param!("0x04E7E989D58A17CD279ECA440C5EAA829EFB6F9967AAAD89022ACBE644C39B36"),
                                    call_param!("0x0453AE0C9610197B18B13645C44D3D0A407083D96562E8752AAB3FAB616CECB0"),
                                ],
                                sender_address: contract_address!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"),
                                entry_point_selector: entry_point!("0x0317EB442B72A9FAE758D4FB26830ED0D9F31C8E7DA4DBFF4E8C59EA6A158E7F"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 2,
                                range_check: 7,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 165,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x00A66C346E273CC49510EF2E1620A1A7922135CB86AB227B86E0AFD12243BD90"),
                        transaction_index: TransactionIndex::new_or_panic(
                            4,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x05C71675616B49FB9D16CAC8BEAAA65F62DC5A532E92785055C15C825166DBBF"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"),
                                    call_param!("0x0317EB442B72A9FAE758D4FB26830ED0D9F31C8E7DA4DBFF4E8C59EA6A158E7F"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000004"),
                                    call_param!("0x04BE52041FEE36AB5199771ACF4B5D260D223297E588654E5C9477DF2EFA542A"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000002"),
                                    call_param!("0x00299E2F4B5A873E95E65EB03D31E532EA2CDE43B498B50CD3161145DB5542A5"),
                                    call_param!("0x03D6897CF23DA3BF4FD35CC7A43CCAF7C5EAF8F7C5B9031AC9B09A929204175F"),
                                ],
                                sender_address: contract_address!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"),
                                entry_point_selector: entry_point!("0x027C3334165536F239CFD400ED956EABFF55FC60DE4FB56728B6A4F6B87DB01C"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 2,
                                range_check: 8,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 209,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x05C71675616B49FB9D16CAC8BEAAA65F62DC5A532E92785055C15C825166DBBF"),
                        transaction_index: TransactionIndex::new_or_panic(
                            5,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x060E05C41A6622592A2E2EFF90A9F2E495296A3BE9596E7BC4DFBAFCE00D7A6A"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                                ],
                                sender_address: contract_address!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"),
                                entry_point_selector: entry_point!("0x0218F305395474A84A39307FA5297BE118FE17BF65E27AC5E2DE6617BAA44C64"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 332,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![
                            L2ToL1Message {
                                from_address: contract_address!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"),
                                payload: vec![
                                    l2_to_l1_message_payload_elem!("0x000000000000000000000000000000000000000000000000000000000000000C"),
                                    l2_to_l1_message_payload_elem!("0x0000000000000000000000000000000000000000000000000000000000000022"),
                                ],
                                to_address: contract_address!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                            },
                        ],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x060E05C41A6622592A2E2EFF90A9F2E495296A3BE9596E7BC4DFBAFCE00D7A6A"),
                        transaction_index: TransactionIndex::new_or_panic(
                            6,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x05634F2847140263BA59480AD4781DACC9991D0365145489B27A198EBED2F969"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"),
                                    call_param!("0x05AEE31408163292105D875070F98CB48275B8C87E80380B78D30647E05854D5"),
                                ],
                                sender_address: contract_address!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"),
                                entry_point_selector: entry_point!("0x019A35A6E95CB7A3318DBB244F20975A1CD8587CC6B5259F15F61D7BEB7EE43B"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 178,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x05634F2847140263BA59480AD4781DACC9991D0365145489B27A198EBED2F969"),
                        transaction_index: TransactionIndex::new_or_panic(
                            7,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x00B049C384CF75174150A2540835CC2ABDCCA1D3A3750298A1741A621983E35A"),
                        variant: DeployV0(
                            DeployTransactionV0 {
                                class_hash: class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                                contract_address: contract_address!("0x06EE3440B08A9C805305449EC7F7003F27E9F7E287B83610952EC36BDC5A6BAE"),
                                contract_address_salt: contract_address_salt!("0x05098705E4D57A8620E5B387855EF4DC82F0CCD84B7299DC1179B87517249127"),
                                constructor_calldata: vec![
                                    constructor_param!("0x048CBA68D4E86764105ADCDCF641AB67B581A55A4F367203647549C8BF1FEEA2"),
                                    constructor_param!("0x0362D24A3B030998AC75E838955DFEE19EC5B6ECEB235B9BFBECCF51B6304D0B"),
                                ],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 29,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x00B049C384CF75174150A2540835CC2ABDCCA1D3A3750298A1741A621983E35A"),
                        transaction_index: TransactionIndex::new_or_panic(
                            8,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x0227F3D9D5CE6680BDF2991576C1A90ACA8184CA26055BAE92D16C58E3E13340"),
                        variant: DeployV0(
                            DeployTransactionV0 {
                                class_hash: class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                                contract_address: contract_address!("0x0735596016A37EE972C42ADEF6A3CF628C19BB3794369C65D2C82BA034AECF2C"),
                                contract_address_salt: contract_address_salt!("0x0060BC7461113E4AF46FD52E5ECBC5C3F4BE92ED7F1329D53721F9BFBC0370CC"),
                                constructor_calldata: vec![
                                    constructor_param!("0x002F50710449A06A9FA789B3C029A63BD0B1F722F46505828A9F815CF91B31D8"),
                                    constructor_param!("0x02A222E62EABE91ABDB6838FA8B267FFE81A6EB575F61E96EC9AA4460C0925A2"),
                                ],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 29,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x0227F3D9D5CE6680BDF2991576C1A90ACA8184CA26055BAE92D16C58E3E13340"),
                        transaction_index: TransactionIndex::new_or_panic(
                            9,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x0376FF82431B52CA1FBC4942DE80BC1B01D8E5CD1EEAB5A277B601B510F2CAB2"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x01E2CD4B3588E8F6F9C4E89FB0E293BF92018C96D7A93EE367D29A284223B6FF"),
                                    call_param!("0x071D1E9D188C784A0BDE95C1D508877A0D93E9102B37213D1E13F3EBC54A7751"),
                                ],
                                sender_address: contract_address!("0x06EE3440B08A9C805305449EC7F7003F27E9F7E287B83610952EC36BDC5A6BAE"),
                                entry_point_selector: entry_point!("0x03D7905601C217734671143D457F0DB37F7F8883112ABD34B92C4ABFEAFDE0C3"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 25,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x0376FF82431B52CA1FBC4942DE80BC1B01D8E5CD1EEAB5A277B601B510F2CAB2"),
                        transaction_index: TransactionIndex::new_or_panic(
                            10,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x025F20C74821D84F62989A71FCEEF08C967837B63BAE31B279A11343F10D874A"),
                        variant: DeployV0(
                            DeployTransactionV0 {
                                class_hash: class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                                contract_address: contract_address!("0x031C887D82502CEB218C06EBB46198DA3F7B92864A8223746BC836DDA3E34B52"),
                                contract_address_salt: contract_address_salt!("0x063D1A6F8130958509E2E695C25B147F43F66F56BBA49FDDB7EE363D8F57A774"),
                                constructor_calldata: vec![
                                    constructor_param!("0x00DF28E613C065616A2E79CA72F9C1908E17B8C913972A9993DA77588DC9CAE9"),
                                    constructor_param!("0x01432126AC23C7028200E443169C2286F99CDB5A7BF22E607BCD724EFA059040"),
                                ],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 29,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x025F20C74821D84F62989A71FCEEF08C967837B63BAE31B279A11343F10D874A"),
                        transaction_index: TransactionIndex::new_or_panic(
                            11,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x02D10272A8BA726793FD15AA23A1E3C42447D7483EBB0B49DF8B987590FE0055"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x0735596016A37EE972C42ADEF6A3CF628C19BB3794369C65D2C82BA034AECF2C"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                                ],
                                sender_address: contract_address!("0x031C887D82502CEB218C06EBB46198DA3F7B92864A8223746BC836DDA3E34B52"),
                                entry_point_selector: entry_point!("0x0218F305395474A84A39307FA5297BE118FE17BF65E27AC5E2DE6617BAA44C64"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 332,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![
                            L2ToL1Message {
                                from_address: contract_address!("0x031C887D82502CEB218C06EBB46198DA3F7B92864A8223746BC836DDA3E34B52"),
                                payload: vec![
                                    l2_to_l1_message_payload_elem!("0x000000000000000000000000000000000000000000000000000000000000000C"),
                                    l2_to_l1_message_payload_elem!("0x0000000000000000000000000000000000000000000000000000000000000022"),
                                ],
                                to_address: contract_address!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                            },
                        ],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x02D10272A8BA726793FD15AA23A1E3C42447D7483EBB0B49DF8B987590FE0055"),
                        transaction_index: TransactionIndex::new_or_panic(
                            12,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x00B05BA5CD0B9E0464D2C1790AD93A159C6EF0594513758BCA9111E74E4099D4"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x031C887D82502CEB218C06EBB46198DA3F7B92864A8223746BC836DDA3E34B52"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                                ],
                                sender_address: contract_address!("0x0735596016A37EE972C42ADEF6A3CF628C19BB3794369C65D2C82BA034AECF2C"),
                                entry_point_selector: entry_point!("0x0218F305395474A84A39307FA5297BE118FE17BF65E27AC5E2DE6617BAA44C64"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 238,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x00B05BA5CD0B9E0464D2C1790AD93A159C6EF0594513758BCA9111E74E4099D4"),
                        transaction_index: TransactionIndex::new_or_panic(
                            13,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x04D16393D940FB4A97F20B9034E2A5E954201FEE827B2B5C6DAA38EC272E7C9C"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x01A7CF8B8027EC2D8FD04F1277F3F8AE6379CA957C5FEC9EE7F59D56D86A26E4"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000002"),
                                    call_param!("0x028DFF6722AA73281B2CF84CAC09950B71FA90512DB294D2042119ABDD9F4B87"),
                                    call_param!("0x057A8F8A019CCAB5BFC6FF86C96B1392257ABB8D5D110C01D326B94247AF161C"),
                                ],
                                sender_address: contract_address!("0x06EE3440B08A9C805305449EC7F7003F27E9F7E287B83610952EC36BDC5A6BAE"),
                                entry_point_selector: entry_point!("0x0317EB442B72A9FAE758D4FB26830ED0D9F31C8E7DA4DBFF4E8C59EA6A158E7F"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 2,
                                range_check: 7,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 169,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x04D16393D940FB4A97F20B9034E2A5E954201FEE827B2B5C6DAA38EC272E7C9C"),
                        transaction_index: TransactionIndex::new_or_panic(
                            14,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x009E80672EDD4927A79F5384E656416B066F8EF58238227AC0FCEA01952B70B5"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x06EE3440B08A9C805305449EC7F7003F27E9F7E287B83610952EC36BDC5A6BAE"),
                                    call_param!("0x05F750DC13ED239FA6FC43FF6E10AE9125A33BD05EC034FC3BB4DD168DF3505F"),
                                ],
                                sender_address: contract_address!("0x031C887D82502CEB218C06EBB46198DA3F7B92864A8223746BC836DDA3E34B52"),
                                entry_point_selector: entry_point!("0x019A35A6E95CB7A3318DBB244F20975A1CD8587CC6B5259F15F61D7BEB7EE43B"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 178,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x009E80672EDD4927A79F5384E656416B066F8EF58238227AC0FCEA01952B70B5"),
                        transaction_index: TransactionIndex::new_or_panic(
                            15,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x0387B5B63E40D4426754895FE52ADF668CF8FDE2A02AA9B6D761873F31AF3462"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x0449908C349E90F81AB13042B1E49DC251EB6E3E51092D9A40F86859F7F415B0"),
                                    call_param!("0x02670B3A8266D5046696A4B79F7433D117D3A19166F15BBD8585822C4E9B7491"),
                                ],
                                sender_address: contract_address!("0x06EE3440B08A9C805305449EC7F7003F27E9F7E287B83610952EC36BDC5A6BAE"),
                                entry_point_selector: entry_point!("0x03D7905601C217734671143D457F0DB37F7F8883112ABD34B92C4ABFEAFDE0C3"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 25,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x0387B5B63E40D4426754895FE52ADF668CF8FDE2A02AA9B6D761873F31AF3462"),
                        transaction_index: TransactionIndex::new_or_panic(
                            16,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x04F0CDFF0D72FC758413A16DB2BC7580DFEC7889A8B921F0FE08641FA265E997"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x0449908C349E90F81AB13042B1E49DC251EB6E3E51092D9A40F86859F7F415B0"),
                                    call_param!("0x06CB6104279E754967A721B52BCF5BE525FDC11FA6DB6EF5C3A4DB832ACF7804"),
                                ],
                                sender_address: contract_address!("0x06EE3440B08A9C805305449EC7F7003F27E9F7E287B83610952EC36BDC5A6BAE"),
                                entry_point_selector: entry_point!("0x03D7905601C217734671143D457F0DB37F7F8883112ABD34B92C4ABFEAFDE0C3"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 25,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x04F0CDFF0D72FC758413A16DB2BC7580DFEC7889A8B921F0FE08641FA265E997"),
                        transaction_index: TransactionIndex::new_or_panic(
                            17,
                        ),
                    },
                    vec![],
                ),
            ],
            state_update: StateUpdate {
                block_hash: block_hash!("0x047C3637B57C2B079B93C61539950C17E868A28F46CDEF28F88521067F21E943"),
                parent_state_commitment: state_commitment!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                state_commitment: state_commitment!("0x021870BA80540E7831FB21C591EE93481F5AE1BB71FF85A86DDD465BE4EDDEE6"),
                contract_updates: HashMap::from_iter([
                    (contract_address!("0x031C9CDB9B00CB35CF31C05855C0EC3ECF6F7952A1CE6E3C53C3455FCD75A280"), ContractUpdate {
                        storage: HashMap::from_iter([
                            (storage_address!("0x05FAC6815FDDF6AF1CA5E592359862EDE14F171E1544FD9E792288164097C35D"), storage_value!("0x00299E2F4B5A873E95E65EB03D31E532EA2CDE43B498B50CD3161145DB5542A5")),
                            (storage_address!("0x05FAC6815FDDF6AF1CA5E592359862EDE14F171E1544FD9E792288164097C35E"), storage_value!("0x03D6897CF23DA3BF4FD35CC7A43CCAF7C5EAF8F7C5B9031AC9B09A929204175F")),
                            (storage_address!("0x0000000000000000000000000000000000000000000000000000000000000005"), storage_value!("0x0000000000000000000000000000000000000000000000000000000000000065")),
                            (storage_address!("0x00CFC2E2866FD08BFB4AC73B70E0C136E326AE18FC797A2C090C8811C695577E"), storage_value!("0x05F1DD5A5AEF88E0498EECA4E7B2EA0FA7110608C11531278742F0B5499AF4B3")),
                            (storage_address!("0x05AEE31408163292105D875070F98CB48275B8C87E80380B78D30647E05854D5"), storage_value!("0x00000000000000000000000000000000000000000000000000000000000007C7")),
                        ]),
                        class: Some(
                            Deploy(
                                class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                            ),
                        ),
                        nonce: None,
                    }),
                    (contract_address!("0x031C887D82502CEB218C06EBB46198DA3F7B92864A8223746BC836DDA3E34B52"), ContractUpdate {
                        storage: HashMap::from_iter([
                            (storage_address!("0x05F750DC13ED239FA6FC43FF6E10AE9125A33BD05EC034FC3BB4DD168DF3505F"), storage_value!("0x00000000000000000000000000000000000000000000000000000000000007C7")),
                            (storage_address!("0x00DF28E613C065616A2E79CA72F9C1908E17B8C913972A9993DA77588DC9CAE9"), storage_value!("0x01432126AC23C7028200E443169C2286F99CDB5A7BF22E607BCD724EFA059040")),
                        ]),
                        class: Some(
                            Deploy(
                                class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                            ),
                        ),
                        nonce: None,
                    }),
                    (contract_address!("0x020CFA74EE3564B4CD5435CDACE0F9C4D43B939620E4A0BB5076105DF0A626C6"), ContractUpdate {
                        storage: HashMap::from_iter([
                            (storage_address!("0x0313AD57FDF765ADDC71329ABF8D74AC2BCE6D46DA8C2B9B82255A5076620300"), storage_value!("0x04E7E989D58A17CD279ECA440C5EAA829EFB6F9967AAAD89022ACBE644C39B36")),
                            (storage_address!("0x05AEE31408163292105D875070F98CB48275B8C87E80380B78D30647E05854D5"), storage_value!("0x00000000000000000000000000000000000000000000000000000000000007E5")),
                            (storage_address!("0x0313AD57FDF765ADDC71329ABF8D74AC2BCE6D46DA8C2B9B82255A5076620301"), storage_value!("0x0453AE0C9610197B18B13645C44D3D0A407083D96562E8752AAB3FAB616CECB0")),
                            (storage_address!("0x06CF6C2F36D36B08E591E4489E92CA882BB67B9C39A3AFCCF011972A8DE467F0"), storage_value!("0x07AB344D88124307C07B56F6C59C12F4543E9C96398727854A322DEA82C73240")),
                            (storage_address!("0x0000000000000000000000000000000000000000000000000000000000000005"), storage_value!("0x000000000000000000000000000000000000000000000000000000000000022B")),
                        ]),
                        class: Some(
                            Deploy(
                                class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                            ),
                        ),
                        nonce: None,
                    }),
                    (contract_address!("0x06EE3440B08A9C805305449EC7F7003F27E9F7E287B83610952EC36BDC5A6BAE"), ContractUpdate {
                        storage: HashMap::from_iter([
                            (storage_address!("0x05BDAF1D47B176BFCD1114809AF85A46B9C4376E87E361D86536F0288A284B66"), storage_value!("0x057A8F8A019CCAB5BFC6FF86C96B1392257ABB8D5D110C01D326B94247AF161C")),
                            (storage_address!("0x05BDAF1D47B176BFCD1114809AF85A46B9C4376E87E361D86536F0288A284B65"), storage_value!("0x028DFF6722AA73281B2CF84CAC09950B71FA90512DB294D2042119ABDD9F4B87")),
                            (storage_address!("0x048CBA68D4E86764105ADCDCF641AB67B581A55A4F367203647549C8BF1FEEA2"), storage_value!("0x0362D24A3B030998AC75E838955DFEE19EC5B6ECEB235B9BFBECCF51B6304D0B")),
                            (storage_address!("0x05F750DC13ED239FA6FC43FF6E10AE9125A33BD05EC034FC3BB4DD168DF3505F"), storage_value!("0x00000000000000000000000000000000000000000000000000000000000007E5")),
                            (storage_address!("0x01E2CD4B3588E8F6F9C4E89FB0E293BF92018C96D7A93EE367D29A284223B6FF"), storage_value!("0x071D1E9D188C784A0BDE95C1D508877A0D93E9102B37213D1E13F3EBC54A7751")),
                            (storage_address!("0x0449908C349E90F81AB13042B1E49DC251EB6E3E51092D9A40F86859F7F415B0"), storage_value!("0x06CB6104279E754967A721B52BCF5BE525FDC11FA6DB6EF5C3A4DB832ACF7804")),
                        ]),
                        class: Some(
                            Deploy(
                                class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                            ),
                        ),
                        nonce: None,
                    }),
                    (contract_address!("0x0735596016A37EE972C42ADEF6A3CF628C19BB3794369C65D2C82BA034AECF2C"), ContractUpdate {
                        storage: HashMap::from_iter([
                            (storage_address!("0x002F50710449A06A9FA789B3C029A63BD0B1F722F46505828A9F815CF91B31D8"), storage_value!("0x02A222E62EABE91ABDB6838FA8B267FFE81A6EB575F61E96EC9AA4460C0925A2")),
                            (storage_address!("0x0000000000000000000000000000000000000000000000000000000000000005"), storage_value!("0x0000000000000000000000000000000000000000000000000000000000000064")),
                        ]),
                        class: Some(
                            Deploy(
                                class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                            ),
                        ),
                        nonce: None,
                    }),
                ]),
                system_contract_updates: Default::default(),
                declared_cairo_classes: Default::default(),
                declared_sierra_classes: Default::default(),
            },
            cairo_defs: Default::default(),
            sierra_defs: Default::default(),
        },
        Block {
            header: SignedBlockHeader {
                header: BlockHeader {
                    hash: block_hash!("0x02A70FB03FE363A2D6BE843343A1D81CE6ABEDA1E9BD5CC6AD8FA9F45E30FDEB"),
                    parent_hash: block_hash!("0x047C3637B57C2B079B93C61539950C17E868A28F46CDEF28F88521067F21E943"),
                    number: BlockNumber::new_or_panic(1),
                    timestamp: BlockTimestamp::new_or_panic(
                        1637072695,
                    ),
                    eth_l1_gas_price: GasPrice(0),
                    strk_l1_gas_price: GasPrice(0),
                    eth_l1_data_gas_price: GasPrice(1),
                    strk_l1_data_gas_price: GasPrice(1),
                    sequencer_address: Default::default(),
                    starknet_version: StarknetVersion::default(),
                    class_commitment: class_commitment!("0x0"),
                    event_commitment: event_commitment!("0x0"),
                    state_commitment: state_commitment!("0x0525AED4DA9CC6CCE2DE31BA79059546B0828903279E4EAA38768DE33E2CAC32"),
                    storage_commitment: storage_commitment!("0x0525AED4DA9CC6CCE2DE31BA79059546B0828903279E4EAA38768DE33E2CAC32"),
                    transaction_commitment: transaction_commitment!("0x040BA52F90B741CD059DBDBACAD788D327E7C8C89DD258881043FD969CDAD86E"),
                    transaction_count: 8,
                    event_count: 0,
                    l1_da_mode: L1DataAvailabilityMode::Calldata,
                    receipt_commitment: receipt_commitment!("0x00FB6833B56FCA428975B0DF7875F35B7EADBD26B517DAF1B9702E1D85665065"),
                    state_diff_commitment: state_diff_commitment!("0x013BEED68D79C0FF1D6B465660BCF245A7F0EC11AF5E9C6564FBA30543705FE3"),
                    state_diff_length: 12,
                },
                signature: BlockCommitmentSignature {
                    r: block_commitment_signature_elem!("0x05C328D673C07E530A45D6F12E569DF0D059D97BF920D978E44DAA54FB3DB655"),
                    s: block_commitment_signature_elem!("0x037FEBA468C96099A9A610C34BAB6230AF8C7E9D78C1DDB7436488961FC5161D")
                },
            },
            transaction_data: vec![
                (
                    Transaction {
                        hash: transaction_hash!("0x02F07A65F9F7A6445B2A0B1FB90EF12F5FD3B94128D06A67712EFD3B2F163533"),
                        variant: DeployV0(
                            DeployTransactionV0 {
                                class_hash: class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                                contract_address: contract_address!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"),
                                contract_address_salt: contract_address_salt!("0x03A6B18FC3415B7D749F18483393B0D6A1AEF168435016C0F5F5D8902A84A36F"),
                                constructor_calldata: vec![
                                    constructor_param!("0x04184FA5A6D40F47A127B046ED6FACFA3E6BC3437B393DA65CC74AFE47CA6C6E"),
                                    constructor_param!("0x001EF78E458502CD457745885204A4AE89F3880EC24DB2D8CA97979DCE15FEDC"),
                                ],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 29,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x02F07A65F9F7A6445B2A0B1FB90EF12F5FD3B94128D06A67712EFD3B2F163533"),
                        transaction_index: TransactionIndex::new_or_panic(
                            0,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x0214C14F39B8AA2DCECFDCA68E540957624E8DB6C3A9012939FF1399975910A0"),
                        variant: DeployV0(
                            DeployTransactionV0 {
                                class_hash: class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                                contract_address: contract_address!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"),
                                contract_address_salt: contract_address_salt!("0x0090677B5114F8DF8BB7DD5E57A90CCEABE385540CB0CA857ED68E22BD76E20A"),
                                constructor_calldata: vec![
                                    constructor_param!("0x010212FA2BE788E5D943714D6A9EAC5E07D8B4B48EAD96B8D0A0CBE7A6DC3832"),
                                    constructor_param!("0x008A81230A7E3FFA40ABE541786A9B69FBB601434CEC9536D5D5B2EE4DF90383"),
                                ],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 29,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x0214C14F39B8AA2DCECFDCA68E540957624E8DB6C3A9012939FF1399975910A0"),
                        transaction_index: TransactionIndex::new_or_panic(
                            1,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x071EED7F033331C8D7BD1A4DCA8EEDF16951A904DE3E195005E49AAE9E502CA6"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                                ],
                                sender_address: contract_address!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"),
                                entry_point_selector: entry_point!("0x0218F305395474A84A39307FA5297BE118FE17BF65E27AC5E2DE6617BAA44C64"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 238,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x071EED7F033331C8D7BD1A4DCA8EEDF16951A904DE3E195005E49AAE9E502CA6"),
                        transaction_index: TransactionIndex::new_or_panic(
                            2,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x01059391B8C4FBA9743B531BA371908195CCB5DCF2A9532FAC247256FB48912F"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"),
                                    call_param!("0x0317EB442B72A9FAE758D4FB26830ED0D9F31C8E7DA4DBFF4E8C59EA6A158E7F"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000004"),
                                    call_param!("0x05BD24B507FCC2FD77DC7847BABB8DF01363D58E9B0BBCD2D06D982E1F3E0C86"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000002"),
                                    call_param!("0x026B5943D4A0C420607CEE8030A8CDD859BF2814A06633D165820960A42C6AED"),
                                    call_param!("0x01518EEC76AFD5397CEFD14EDA48D01AD59981F9CE9E70C233CA67ACD8754008"),
                                ],
                                sender_address: contract_address!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"),
                                entry_point_selector: entry_point!("0x027C3334165536F239CFD400ED956EABFF55FC60DE4FB56728B6A4F6B87DB01C"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 2,
                                range_check: 8,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 209,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x01059391B8C4FBA9743B531BA371908195CCB5DCF2A9532FAC247256FB48912F"),
                        transaction_index: TransactionIndex::new_or_panic(
                            3,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x073FE0B59AC28A2C3C28B4D8713F4F84D4463C48245539644838CF1E8526B536"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                                ],
                                sender_address: contract_address!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"),
                                entry_point_selector: entry_point!("0x0218F305395474A84A39307FA5297BE118FE17BF65E27AC5E2DE6617BAA44C64"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 332,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![
                            L2ToL1Message {
                                from_address: contract_address!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"),
                                payload: vec![
                                    l2_to_l1_message_payload_elem!("0x000000000000000000000000000000000000000000000000000000000000000C"),
                                    l2_to_l1_message_payload_elem!("0x0000000000000000000000000000000000000000000000000000000000000022"),
                                ],
                                to_address: contract_address!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                            },
                        ],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x073FE0B59AC28A2C3C28B4D8713F4F84D4463C48245539644838CF1E8526B536"),
                        transaction_index: TransactionIndex::new_or_panic(
                            4,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x0169D35E8210A26FD2439207D77EF2F0ABE77471ACBC2DA8D5EEAB5127D8D57B"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x0000000000000000000000009C47C96A115DAD3A7DBBDAFB2369FDAA2835D0D4"),
                                ],
                                sender_address: contract_address!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"),
                                entry_point_selector: entry_point!("0x012EAD94AE9D3F9D2BDB6B847CF255F1F398193A1F88884A0AE8E18F24A037B6"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 31,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![
                            L2ToL1Message {
                                from_address: contract_address!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"),
                                payload: vec![
                                    l2_to_l1_message_payload_elem!("0x000000000000000000000000000000000000000000000000000000000000000C"),
                                    l2_to_l1_message_payload_elem!("0x0000000000000000000000000000000000000000000000000000000000000022"),
                                ],
                                to_address: contract_address!("0x0000000000000000000000009C47C96A115DAD3A7DBBDAFB2369FDAA2835D0D4"),
                            },
                        ],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x0169D35E8210A26FD2439207D77EF2F0ABE77471ACBC2DA8D5EEAB5127D8D57B"),
                        transaction_index: TransactionIndex::new_or_panic(
                            5,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x068A8426D72BCAC7DC3C84C52D90F39F64FFDC10E50B86F8D6F047EE243E2BA1"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x02C4301154E2F60000CE44AF78B14619806DDA3B52ABE8BC224D49765A0924C1"),
                                    call_param!("0x0000000000000000000000000000000000000000000000000000000000000002"),
                                    call_param!("0x02B36318931915F71777F7E59246ECAB3189DB48408952CEFDA72F4B7977BE51"),
                                    call_param!("0x07E928DCF189B05E4A3DAE0BC2CB98E447F1843F7DEBBBF574151EB67CDA8797"),
                                ],
                                sender_address: contract_address!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"),
                                entry_point_selector: entry_point!("0x0317EB442B72A9FAE758D4FB26830ED0D9F31C8E7DA4DBFF4E8C59EA6A158E7F"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 2,
                                range_check: 7,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 165,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x068A8426D72BCAC7DC3C84C52D90F39F64FFDC10E50B86F8D6F047EE243E2BA1"),
                        transaction_index: TransactionIndex::new_or_panic(
                            6,
                        ),
                    },
                    vec![],
                ),
                (
                    Transaction {
                        hash: transaction_hash!("0x07EFF4524AE42C2FFA72FF228CEE4729BF7F31C2A0AEFE3EE1C8ABE546442158"),
                        variant: InvokeV0(
                            InvokeTransactionV0 {
                                calldata: vec![
                                    call_param!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"),
                                    call_param!("0x01AED933FD362FAECD8EA54EE749092BD21F89901B7D1872312584AC5B636C6D"),
                                ],
                                sender_address: contract_address!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"),
                                entry_point_selector: entry_point!("0x019A35A6E95CB7A3318DBB244F20975A1CD8587CC6B5259F15F61D7BEB7EE43B"),
                                entry_point_type: None,
                                max_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                                signature: vec![],
                            },
                        ),
                    },
                    Receipt {
                        actual_fee: Fee(felt!("0x0000000000000000000000000000000000000000000000000000000000000000")),
                        execution_resources: ExecutionResources {
                            builtins: BuiltinCounters {
                                output: 0,
                                pedersen: 0,
                                range_check: 0,
                                ecdsa: 0,
                                bitwise: 0,
                                ec_op: 0,
                                keccak: 0,
                                poseidon: 0,
                                segment_arena: 0,
                                add_mod: 0,
                                mul_mod: 0,
                                range_check96: 0,
                            },
                            n_steps: 178,
                            n_memory_holes: 0,
                            data_availability: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                            total_gas_consumed: L1Gas {
                                l1_gas: 0,
                                l1_data_gas: 0,
                            },
                        },
                        l2_to_l1_messages: vec![],
                        execution_status: Succeeded,
                        transaction_hash: transaction_hash!("0x07EFF4524AE42C2FFA72FF228CEE4729BF7F31C2A0AEFE3EE1C8ABE546442158"),
                        transaction_index: TransactionIndex::new_or_panic(
                            7,
                        ),
                    },
                    vec![],
                ),
            ],
            state_update: StateUpdate {
                block_hash: block_hash!("0x02A70FB03FE363A2D6BE843343A1D81CE6ABEDA1E9BD5CC6AD8FA9F45E30FDEB"),
                parent_state_commitment: state_commitment!("0x021870BA80540E7831FB21C591EE93481F5AE1BB71FF85A86DDD465BE4EDDEE6"),
                state_commitment: state_commitment!("0x0525AED4DA9CC6CCE2DE31BA79059546B0828903279E4EAA38768DE33E2CAC32"),
                contract_updates: HashMap::from_iter([
                    (contract_address!("0x06538FDD3AA353AF8A87F5FE77D1F533EA82815076E30A86D65B72D3EB4F0B80"), ContractUpdate {
                        storage: HashMap::from_iter([
                            (storage_address!("0x00FFDA4B5CF0DCE9BC9B0D035210590C73375FDBB70CD94EC6949378BFFC410D"), storage_value!("0x07E928DCF189B05E4A3DAE0BC2CB98E447F1843F7DEBBBF574151EB67CDA8797")),
                            (storage_address!("0x00FFDA4B5CF0DCE9BC9B0D035210590C73375FDBB70CD94EC6949378BFFC410C"), storage_value!("0x02B36318931915F71777F7E59246ECAB3189DB48408952CEFDA72F4B7977BE51")),
                            (storage_address!("0x01AED933FD362FAECD8EA54EE749092BD21F89901B7D1872312584AC5B636C6D"), storage_value!("0x00000000000000000000000000000000000000000000000000000000000007E5")),
                            (storage_address!("0x010212FA2BE788E5D943714D6A9EAC5E07D8B4B48EAD96B8D0A0CBE7A6DC3832"), storage_value!("0x008A81230A7E3FFA40ABE541786A9B69FBB601434CEC9536D5D5B2EE4DF90383")),
                            (storage_address!("0x0000000000000000000000000000000000000000000000000000000000000005"), storage_value!("0x000000000000000000000000000000000000000000000000000000000000022B")),
                        ]),
                        class: Some(
                            Deploy(
                                class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                            ),
                        ),
                        nonce: None,
                    }),
                    (contract_address!("0x0327D34747122D7A40F4670265B098757270A449EC80C4871450FFFDAB7C2FA8"), ContractUpdate {
                        storage: HashMap::from_iter([
                            (storage_address!("0x04184FA5A6D40F47A127B046ED6FACFA3E6BC3437B393DA65CC74AFE47CA6C6E"), storage_value!("0x001EF78E458502CD457745885204A4AE89F3880EC24DB2D8CA97979DCE15FEDC")),
                            (storage_address!("0x0000000000000000000000000000000000000000000000000000000000000005"), storage_value!("0x0000000000000000000000000000000000000000000000000000000000000065")),
                            (storage_address!("0x01AED933FD362FAECD8EA54EE749092BD21F89901B7D1872312584AC5B636C6D"), storage_value!("0x00000000000000000000000000000000000000000000000000000000000007C7")),
                            (storage_address!("0x05591C8C3C8D154A30869B463421CD5933770A0241E1A6E8EBCBD91BDD69BEC4"), storage_value!("0x026B5943D4A0C420607CEE8030A8CDD859BF2814A06633D165820960A42C6AED")),
                            (storage_address!("0x05591C8C3C8D154A30869B463421CD5933770A0241E1A6E8EBCBD91BDD69BEC5"), storage_value!("0x01518EEC76AFD5397CEFD14EDA48D01AD59981F9CE9E70C233CA67ACD8754008")),
                        ]),
                        class: Some(
                            Deploy(
                                class_hash!("0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8"),
                            ),
                        ),
                        nonce: None,
                    }),
                ]),
                system_contract_updates: Default::default(),
                declared_cairo_classes: Default::default(),
                declared_sierra_classes: Default::default(),
            },
            cairo_defs: Default::default(),
            sierra_defs: Default::default(),
        },
    ]
}
