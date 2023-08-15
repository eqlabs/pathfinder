use stark_hash::{Felt, HashChain};

use crate::{felt_bytes, prelude::*};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub hash: TransactionHash,
    pub variant: TransactionVariant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionVariant {
    DeclareV0(DeclareTransactionV0V1),
    DeclareV1(DeclareTransactionV0V1),
    DeclareV2(DeclareTransactionV2),
    // Regenesis: deploy is a legacy variant and can be removed after regenesis.
    Deploy(DeployTransaction),
    DeployAccount(DeployAccountTransaction),
    InvokeV0(InvokeTransactionV0),
    InvokeV1(InvokeTransactionV1),
    L1Handler(L1HandlerTransaction),
}

impl Transaction {
    /// Note that this calculates and uses the variants hash.
    pub fn from_variant(variant: TransactionVariant, chain_id: ChainId) -> Self {
        let hash = variant.calculate_hash(chain_id);

        Self { hash, variant }
    }
}

impl From<DeclareTransactionV2> for TransactionVariant {
    fn from(value: DeclareTransactionV2) -> Self {
        Self::DeclareV2(value)
    }
}
impl From<DeployTransaction> for TransactionVariant {
    fn from(value: DeployTransaction) -> Self {
        Self::Deploy(value)
    }
}
impl From<DeployAccountTransaction> for TransactionVariant {
    fn from(value: DeployAccountTransaction) -> Self {
        Self::DeployAccount(value)
    }
}
impl From<InvokeTransactionV0> for TransactionVariant {
    fn from(value: InvokeTransactionV0) -> Self {
        Self::InvokeV0(value)
    }
}
impl From<InvokeTransactionV1> for TransactionVariant {
    fn from(value: InvokeTransactionV1) -> Self {
        Self::InvokeV1(value)
    }
}
impl From<L1HandlerTransaction> for TransactionVariant {
    fn from(value: L1HandlerTransaction) -> Self {
        Self::L1Handler(value)
    }
}

impl TransactionVariant {
    pub const fn kind(&self) -> &str {
        use TransactionVariant::*;
        match self {
            DeclareV0(_) => "DeclareV0",
            DeclareV1(_) => "DeclareV1",
            DeclareV2(_) => "DeclareV2",
            Deploy(_) => "Deploy",
            DeployAccount(_) => "DeployAccount",
            InvokeV0(_) => "InvokeV0",
            InvokeV1(_) => "InvokeV1",
            L1Handler(_) => "L1Handler",
        }
    }
    /// Calcualtes the [TransactionHash] of this transaction.
    ///
    /// #### WARNING: only guaranteed to be correct for transactions from starknet 0.8 onwards.
    ///
    /// More specifically:
    /// ```
    /// mainnet       4 399
    /// testnet     306 700
    /// testnet2     21 086  (early blocks used the wrong chain ID)
    /// integration TBD
    /// ```
    pub fn calculate_hash(&self, chain_id: ChainId) -> TransactionHash {
        use TransactionVariant::*;
        let prefix = match self {
            DeclareV0(_) | DeclareV1(_) | DeclareV2(_) => felt_bytes!(b"declare"),
            Deploy(_) => felt_bytes!(b"deploy"),
            DeployAccount(_) => felt_bytes!(b"deploy_account"),
            InvokeV0(_) | InvokeV1(_) => felt_bytes!(b"invoke"),
            L1Handler(_) => felt_bytes!(b"l1_handler"),
        };

        let version = match self {
            DeclareV0(_) => TransactionVersion::ZERO,
            DeclareV1(_) => TransactionVersion::ONE,
            DeclareV2(_) => TransactionVersion::TWO,
            Deploy(tx) => tx.version,
            DeployAccount(tx) => tx.version,
            InvokeV0(_) => TransactionVersion::ZERO,
            InvokeV1(_) => TransactionVersion::ONE,
            L1Handler(tx) => tx.version,
        };
        // FIXME: why is transaction version not a felt?
        let version =
            Felt::from_be_slice(version.0.as_bytes()).expect("Version should convert to felt");

        let address = match self {
            DeclareV0(tx) => tx.sender_address,
            DeclareV1(tx) => tx.sender_address,
            DeclareV2(tx) => tx.sender_address,
            Deploy(tx) => tx.contract_address,
            DeployAccount(tx) => tx.contract_address,
            InvokeV0(tx) => tx.sender_address,
            InvokeV1(tx) => tx.sender_address,
            L1Handler(tx) => tx.contract_address,
        };

        let entry_point = match self {
            DeclareV0(_) | DeclareV1(_) | DeclareV2(_) | DeployAccount(_) | InvokeV1(_) => {
                Default::default()
            }
            Deploy(_) => EntryPoint::CONSTRUCTOR,
            InvokeV0(tx) => tx.entry_point_selector,
            L1Handler(tx) => tx.entry_point_selector,
        };

        let list_hash = match self {
            DeclareV0(_) => HashChain::default().finalize(),
            DeclareV1(tx) => HashChain::default()
                .chain_update(tx.class_hash.0)
                .finalize(),
            DeclareV2(tx) => HashChain::default()
                .chain_update(tx.class_hash.0)
                .finalize(),
            Deploy(tx) => tx
                .constructor_calldata
                .iter()
                .fold(HashChain::default(), |mut hh, constructor_param| {
                    hh.update(constructor_param.0);
                    hh
                })
                .finalize(),
            DeployAccount(tx) => {
                let hash = HashChain::default()
                    .chain_update(tx.class_hash.0)
                    .chain_update(tx.contract_address_salt.0);
                tx.constructor_calldata
                    .iter()
                    .fold(hash, |mut hash, constructor_param| {
                        hash.update(constructor_param.0);
                        hash
                    })
                    .finalize()
            }
            InvokeV0(tx) => tx
                .calldata
                .iter()
                .fold(HashChain::default(), |mut hash, call_param| {
                    hash.update(call_param.0);
                    hash
                })
                .finalize(),
            InvokeV1(tx) => tx
                .calldata
                .iter()
                .fold(HashChain::default(), |mut hash, call_param| {
                    hash.update(call_param.0);
                    hash
                })
                .finalize(),
            L1Handler(tx) => tx
                .calldata
                .iter()
                .fold(HashChain::default(), |mut hash, call_param| {
                    hash.update(call_param.0);
                    hash
                })
                .finalize(),
        };

        let max_fee = match self {
            DeclareV0(_) | Deploy(_) | L1Handler(_) => Default::default(),
            DeclareV1(tx) => tx.max_fee,
            DeclareV2(tx) => tx.max_fee,
            DeployAccount(tx) => tx.max_fee,
            InvokeV0(tx) => tx.max_fee,
            InvokeV1(tx) => tx.max_fee,
        };

        let tx_nonce = match self {
            // These predate tx nonces and therefore don't have one.
            InvokeV0(_) | Deploy(_) => None,
            // This variant also predates tx nonces, but did use the class hash so we embed that here.
            DeclareV0(tx) => Some(tx.class_hash.0),
            DeclareV1(tx) => Some(tx.nonce.0),
            DeclareV2(tx) => Some(tx.nonce.0),
            DeployAccount(tx) => Some(tx.nonce.0),
            InvokeV1(tx) => Some(tx.nonce.0),
            L1Handler(tx) => Some(tx.nonce.0),
        };

        let casm_hash = match self {
            DeclareV2(tx) => Some(tx.compiled_class_hash),
            _ => None,
        };

        let mut hash = HashChain::default()
            .chain_update(prefix)
            .chain_update(version)
            .chain_update(*address.get())
            .chain_update(entry_point.0)
            .chain_update(list_hash)
            .chain_update(max_fee.0)
            .chain_update(chain_id.0);

        if let Some(tx_nonce) = tx_nonce {
            hash.update(tx_nonce);
        }

        if let Some(casm_hash) = casm_hash {
            hash.update(casm_hash.0);
        }

        TransactionHash(hash.finalize())
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeclareTransactionV0V1 {
    pub class_hash: ClassHash,
    pub max_fee: Fee,
    pub nonce: TransactionNonce,
    pub sender_address: ContractAddress,
    pub signature: Vec<TransactionSignatureElem>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeclareTransactionV2 {
    pub class_hash: ClassHash,
    pub max_fee: Fee,
    pub nonce: TransactionNonce,
    pub sender_address: ContractAddress,
    pub signature: Vec<TransactionSignatureElem>,
    pub compiled_class_hash: CasmHash,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeployTransaction {
    pub contract_address: ContractAddress,
    pub contract_address_salt: ContractAddressSalt,
    pub class_hash: ClassHash,
    pub constructor_calldata: Vec<ConstructorParam>,
    pub version: TransactionVersion,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DeployAccountTransaction {
    pub contract_address: ContractAddress,
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Vec<CallParam>,
    pub class_hash: ClassHash,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct InvokeTransactionV0 {
    pub calldata: Vec<CallParam>,
    pub sender_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub entry_point_type: Option<EntryPointType>,
    pub max_fee: Fee,
    pub signature: Vec<TransactionSignatureElem>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct InvokeTransactionV1 {
    pub calldata: Vec<CallParam>,
    pub sender_address: ContractAddress,
    pub max_fee: Fee,
    pub signature: Vec<TransactionSignatureElem>,
    pub nonce: TransactionNonce,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct L1HandlerTransaction {
    pub contract_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub nonce: TransactionNonce,
    pub calldata: Vec<CallParam>,
    pub version: TransactionVersion,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EntryPointType {
    External,
    L1Handler,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macro_prelude::*;

    mod transaction_hash {

        use super::*;

        #[test]
        fn invoke_v0() {
            let expected = transaction_hash!(
                "0x587d93f2339b7f2beda040187dbfcb9e076ce4a21eb8d15ae64819718817fbe"
            );
            let tx = TransactionVariant::InvokeV0(InvokeTransactionV0 {
                calldata: vec![
                    call_param!("0x3"),
                    call_param!(
                        "0x72df4dc5b6c4df72e4288857317caf2ce9da166ab8719ab8306516a2fddfff7"
                    ),
                    call_param!(
                        "0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"
                    ),
                    call_param!("0x0"),
                    call_param!("0x3"),
                    call_param!(
                        "0x7394cbe418daa16e42b87ba67372d4ab4a5df0b05c6e554d158458ce245bc10"
                    ),
                    call_param!(
                        "0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"
                    ),
                    call_param!("0x3"),
                    call_param!("0x3"),
                    call_param!(
                        "0x4aec73f0611a9be0524e7ef21ab1679bdf9c97dc7d72614f15373d431226b6a"
                    ),
                    call_param!(
                        "0x3f35dbce7a07ce455b128890d383c554afbc1b07cf7390a13e2d602a38c1a0a"
                    ),
                    call_param!("0x6"),
                    call_param!("0xa"),
                    call_param!("0x10"),
                    call_param!(
                        "0x4aec73f0611a9be0524e7ef21ab1679bdf9c97dc7d72614f15373d431226b6a"
                    ),
                    call_param!("0x14934a76f"),
                    call_param!("0x0"),
                    call_param!(
                        "0x4aec73f0611a9be0524e7ef21ab1679bdf9c97dc7d72614f15373d431226b6a"
                    ),
                    call_param!("0x2613cd2f52b54fb440"),
                    call_param!("0x0"),
                    call_param!(
                        "0x72df4dc5b6c4df72e4288857317caf2ce9da166ab8719ab8306516a2fddfff7"
                    ),
                    call_param!(
                        "0x7394cbe418daa16e42b87ba67372d4ab4a5df0b05c6e554d158458ce245bc10"
                    ),
                    call_param!("0x14934a76f"),
                    call_param!("0x0"),
                    call_param!("0x2613cd2f52b54fb440"),
                    call_param!("0x0"),
                    call_param!("0x135740b18"),
                    call_param!("0x0"),
                    call_param!("0x23caeef429e7df66e0"),
                    call_param!("0x0"),
                    call_param!("0x17"),
                ],
                sender_address: contract_address!(
                    "0x7463cdd01f6e6a4f13084ea9eee170298b0bbe3faa17f46924c85bb284d4c98"
                ),
                entry_point_selector: entry_point!(
                    "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
                ),
                entry_point_type: Some(EntryPointType::External),
                signature: vec![
                    transaction_signature_elem!(
                        "0x6e82c6752bd13e29b68cf0c8b0d4eb9133b5a056336a842bff01756e514d04a"
                    ),
                    transaction_signature_elem!(
                        "0xa87f00c9e39fd0711aaea4edae0f00044384188a87f489170ac383e3ad087f"
                    ),
                ],
                max_fee: fee!("0x1ee7b2b881350"),
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn invoke_v1() {
            // Taken from testnet 830 782
            let expected = transaction_hash!(
                "0xe1cd331f61b4359bfc7bb1c3efd35ca9b21d879ef3f5a2694fcd407959cc79"
            );
            let tx = TransactionVariant::InvokeV1(InvokeTransactionV1 {
                calldata: vec![
                    call_param!("0x2"),
                    call_param!(
                        "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
                    ),
                    call_param!(
                        "0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"
                    ),
                    call_param!("0x0"),
                    call_param!("0x3"),
                    call_param!(
                        "0x18a439bcbb1b3535a6145c1dc9bc6366267d923f60a84bd0c7618f33c81d334"
                    ),
                    call_param!(
                        "0x15543c3708653cda9d418b4ccd3be11368e40636c10c44b18cfe756b6d88b29"
                    ),
                    call_param!("0x3"),
                    call_param!("0x6"),
                    call_param!("0x9"),
                    call_param!(
                        "0x18a439bcbb1b3535a6145c1dc9bc6366267d923f60a84bd0c7618f33c81d334"
                    ),
                    call_param!("0x4a9b6384488000"),
                    call_param!("0x0"),
                    call_param!("0x1"),
                    call_param!(
                        "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
                    ),
                    call_param!("0x4a9b6384488000"),
                    call_param!("0x0"),
                    call_param!("0x18b7cb1d1cf"),
                    call_param!("0x0"),
                ],
                sender_address: contract_address!(
                    "0x58a01f55343a298a4344dfcab96d5d81bfd48a4326c5fe13c8c4f036d825335"
                ),
                signature: vec![
                    transaction_signature_elem!(
                        "0xa059255a0bcf742a0e57324030f49a99da8f9e74ee8260e478a245be4c15a0"
                    ),
                    transaction_signature_elem!(
                        "0x738f073051cf3952345c514b2496a615e952bb10898dbf0e41376cd389f840c"
                    ),
                ],
                max_fee: fee!("0x9184e72a0000"),
                nonce: transaction_nonce!("0x10"),
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn declare_v0() {
            let expected = transaction_hash!(
                "0x6d346ba207eb124355960c19c737698ad37a3c920a588b741e0130ff5bd4d6d"
            );
            let tx = TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                class_hash: class_hash!(
                    "0x71e6ef53e53e6f5ca792fc4a5799a33e6f4118e4fd1d948dca3a371506f0cc7"
                ),
                sender_address: contract_address!("0x1"),
                ..Default::default()
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn declare_v1() {
            let expected = transaction_hash!(
                "0x60a9a8c1badb7a0a5bbbd3499c869f44d61578a4f308f486aeb271bc33adc3a"
            );
            let tx = TransactionVariant::DeclareV1(DeclareTransactionV0V1 {
                class_hash: class_hash!(
                    "0x68704d18de8ccf71da7c9761ee53efd44dcfcfd512eddfac9c396e7d175e234"
                ),
                max_fee: fee!("0x174876e8000"),
                sender_address: contract_address!(
                    "0x198dcf77076f4edc644e7faf5918b86eedc1c52e7c42f13d21c4d75e2e2aa71"
                ),
                nonce: transaction_nonce!("0x0"),
                signature: vec![
                    transaction_signature_elem!(
                        "0x25b5e2231f682a7f25ace7544258423459305ec0f4764a2a442de08ffc4dcb4"
                    ),
                    transaction_signature_elem!(
                        "0x39668e451495bbeb762a5a4a3550113c899e51c35542fb59b984e701e5d7d6d"
                    ),
                ],
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn declare_v2() {
            let expected = transaction_hash!(
                "0x4cc334c670486d286f38dc7ffcee2059d5db7f96d60fe64130e4e5a31acc9d3"
            );
            let tx = TransactionVariant::DeclareV2(DeclareTransactionV2 {
                class_hash: class_hash!(
                    "0x43d1ec664972001e26c51c4632354a0dc32e0b13bdbea04fb019fbee6e4c118"
                ),
                max_fee: fee!("0x9a045fc50b3e"),
                nonce: transaction_nonce!("0x3"),
                sender_address: contract_address!(
                    "0x33ba85da43392459a9bd85e1d3094be8a08cf575ab32a384741c061f8c467e2"
                ),
                signature: vec![
                    transaction_signature_elem!(
                        "0x6ea8e4e33be3ce5056a949c680469f4bd1d01a3dca4ca5d96954639a0939612"
                    ),
                    transaction_signature_elem!(
                        "0x75fc2e8e402a1896966258381b53f32610b7df5546f8201fa1966f2272705f6"
                    ),
                ],
                compiled_class_hash: casm_hash!(
                    "0x13f6700f794ccf04bac0f8d1c33b13f8153930e0dbd5c9c6659ffe89b0bc2c3"
                ),
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn deploy_v0() {
            let expected = transaction_hash!(
                "0x7bd95674900c93e1e7aa8fbaf3b99166131d995f547bd33bbf5d915cbf87e4"
            );
            let tx = TransactionVariant::Deploy(DeployTransaction {
                contract_address: contract_address!(
                    "0x7d9d10f80bf2df877c7cd65c7be6064c3facf2e5c5399a3aa81f3e8dc75f759"
                ),
                contract_address_salt: contract_address_salt!(
                    "0x734104a0205f328106ee270b5d2653b28a34e73889feb66e68e73b3923d81b4"
                ),
                class_hash: class_hash!(
                    "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"
                ),
                constructor_calldata: vec![
                    constructor_param!(
                        "0x3e327de1c40540b98d05cbcb13552008e36f0ec8d61d46956d2f9752c294328"
                    ),
                    constructor_param!(
                        "0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463"
                    ),
                    constructor_param!("0x2"),
                    constructor_param!(
                        "0x734104a0205f328106ee270b5d2653b28a34e73889feb66e68e73b3923d81b4"
                    ),
                    constructor_param!("0x0"),
                ],
                version: TransactionVersion::ZERO,
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn deploy_v1() {
            let expected = transaction_hash!(
                "0x790cc8b131a58a28d8f30a96a12dc37bdccd7b9a9d830f28cae713f0f8a3ac2"
            );
            let tx = TransactionVariant::Deploy(DeployTransaction {
                contract_address: contract_address!(
                    "0x690a73743f30f534d960e8dcec36c40e4648427a9669d7cac2924d5be29cee9"
                ),
                contract_address_salt: contract_address_salt!(
                    "0x1f0c06480fbbcf9df67a9780fb13265a26f9a428bb38719375f714f61f7d7cb"
                ),
                class_hash: class_hash!(
                    "0x1e77e6a83dc4d6fb9cc698b0493f40795ec95595971f61750643a85afc99bcc"
                ),
                constructor_calldata: vec![
                    constructor_param!(
                        "0x618b4d6a27e6a97ebb43ddb825c78c5306409658779b6e920e7a00d493e18c"
                    ),
                    constructor_param!(
                        "0x3147ce71f170b879ab4890f52698317d2cd697443e32cca3f1dfc521f473380"
                    ),
                ],
                version: TransactionVersion::ONE,
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn deploy_account() {
            let expected = transaction_hash!(
                "0x1708e522240968ec8283e6bb13c3628ed126fd0e82ec6716ddbc074c3c4119a"
            );
            let tx = TransactionVariant::DeployAccount(DeployAccountTransaction {
                contract_address: contract_address!(
                    "0x3c54ffa250b748560d17beab705ac51aa9ac59c57f069d571a1f738d8e4eea"
                ),
                max_fee: fee!("0xb8d9ee8ad2"),
                version: TransactionVersion::ONE,
                signature: vec![
                    transaction_signature_elem!(
                        "0x7d12a1a4abe296fd5e0260757b5ba98b3223c7bb85eda93f8df7e01d74dbc3e"
                    ),
                    transaction_signature_elem!(
                        "0x18cc1d216f7f61f3b8afd5ef681e1911a405339dabb8590a10ee6bcd3a6a1c6"
                    ),
                ],
                nonce: TransactionNonce::ZERO,
                contract_address_salt: contract_address_salt!(
                    "0x57f53aa8354a085d28b36fed3b24e8934fcb2ba889c68e910e1f357345fb747"
                ),
                constructor_calldata: vec![
                    call_param!(
                        "0x33434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2"
                    ),
                    call_param!("0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463"),
                    call_param!("0x2"),
                    call_param!(
                        "0x57f53aa8354a085d28b36fed3b24e8934fcb2ba889c68e910e1f357345fb747"
                    ),
                    call_param!("0x0"),
                ],
                class_hash: class_hash!(
                    "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"
                ),
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }

        #[test]
        fn l1_handler() {
            let expected = transaction_hash!(
                "0xb11aa5369db77a9705ef108f0bfa6861581b99a54bd068261c0cd3bded2f57"
            );
            let tx = TransactionVariant::L1Handler(L1HandlerTransaction {
                contract_address: contract_address!(
                    "0x73314940630fd6dcda0d772d4c972c4e0a9946bef9dabf4ef84eda8ef542b82"
                ),
                entry_point_selector: entry_point!(
                    "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5"
                ),
                nonce: transaction_nonce!("0x567db"),
                calldata: vec![
                    call_param!("0xc3511006c04ef1d78af4c8e0e74ec18a6e64ff9e"),
                    call_param!("0x37a5019d41f19b0e37616a81ea3984457c3eb12b37cf76089a81ba5ebbbf9"),
                    call_param!("0x2386f26fc10000"),
                    call_param!("0x0"),
                ],
                version: TransactionVersion::ZERO,
            });

            assert_eq!(tx.calculate_hash(ChainId::TESTNET), expected);
        }
    }
}
