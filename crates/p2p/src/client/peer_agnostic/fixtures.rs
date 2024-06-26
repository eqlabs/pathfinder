use std::collections::VecDeque;
use std::sync::Arc;

use fake::{Dummy, Fake, Faker};
use futures::channel::mpsc;
use futures::SinkExt;
use libp2p::PeerId;
use p2p_proto::common::{Address, Hash, VolitionDomain};
use p2p_proto::state::{ContractDiff, ContractStoredValue, DeclaredClass, StateDiffsResponse};
use p2p_proto::transaction::{TransactionWithReceipt, TransactionsResponse};
use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdate, StateUpdateData};
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::{CasmHash, ClassHash, ContractAddress, SierraHash, TransactionIndex};
use tagged::Tagged;
use tagged_debug_derive::TaggedDebug;
use tokio::sync::Mutex;

use super::UnverifiedStateUpdateData;
use crate::client::conv::ToDto;
use crate::client::peer_agnostic::Receipt;

#[derive(Clone, PartialEq, TaggedDebug)]
pub struct TestPeer(pub PeerId);

#[derive(Clone, Dummy, PartialEq, TaggedDebug)]
pub struct TestTxn {
    pub t: TransactionVariant,
    pub r: Receipt,
}

impl TestTxn {
    pub fn new((t, r): (TransactionVariant, Receipt)) -> Self {
        Self { t, r }
    }
}

pub fn peer(tag: i32) -> TestPeer {
    tagged::init();
    Tagged::<TestPeer>::get(format!("peer {tag}"), || TestPeer(PeerId::random()))
        .unwrap()
        .data
}

pub fn unzip_fixtures<T>(
    responses: Vec<Result<(TestPeer, Vec<T>), TestPeer>>,
) -> (Vec<PeerId>, Arc<Mutex<VecDeque<Result<Vec<T>, TestPeer>>>>) {
    let peers = responses
        .iter()
        .map(|r| match r {
            Ok((p, _)) => p.0,
            Err(p) => p.0,
        })
        .collect::<Vec<_>>();
    let responses = Arc::new(Mutex::new(
        responses
            .into_iter()
            .map(|r| r.map(|(_, responses)| responses))
            .collect::<VecDeque<_>>(),
    ));
    (peers, responses)
}

pub async fn send_request<T>(
    responses: Arc<Mutex<VecDeque<Result<Vec<T>, TestPeer>>>>,
) -> anyhow::Result<mpsc::Receiver<T>> {
    let mut guard = responses.lock().await;
    match guard.pop_front() {
        Some(Ok(responses)) => {
            let (mut tx, rx) = mpsc::channel(responses.len() + 1);
            for r in responses {
                tx.send(r).await.unwrap();
            }
            Ok(rx)
        }
        Some(Err(_)) => Err(anyhow::anyhow!("peer failed")),
        None => {
            panic!("fix your assumed responses")
        }
    }
}

pub fn txn_resp(tag: i32, transaction_index: u64) -> TransactionsResponse {
    let TestTxn { t, r } = txn(tag, transaction_index);
    let resp = TransactionsResponse::TransactionWithReceipt(TransactionWithReceipt {
        receipt: (&t, r).to_dto(),
        transaction: t.to_dto(),
    });
    Tagged::get(format!("txn resp {tag}"), || resp)
        .unwrap()
        .data
}

pub fn txn(tag: i32, transaction_index: u64) -> TestTxn {
    Tagged::get(format!("txn {tag}"), || {
        let mut x = Faker.fake::<TestTxn>();
        x.r.transaction_index = TransactionIndex::new_or_panic(transaction_index);
        x
    })
    .unwrap()
    .data
}

pub fn contract_diff(tag: i32) -> StateDiffsResponse {
    let sd = state_diff(tag).state_diff;
    let (a, u) = sd
        .contract_updates
        .into_iter()
        .chain(sd.system_contract_updates.into_iter().map(|(a, u)| {
            (
                a,
                ContractUpdate {
                    storage: u.storage,
                    ..Default::default()
                },
            )
        }))
        .next()
        .unwrap();
    StateDiffsResponse::ContractDiff(
        Tagged::get(format!("contract diff response {tag}"), || ContractDiff {
            address: Address(a.0),
            nonce: u.nonce.map(|x| x.0),
            class_hash: u.class.map(|x| Hash(x.class_hash().0)),
            values: u
                .storage
                .into_iter()
                .map(|(k, v)| ContractStoredValue {
                    key: k.0,
                    value: v.0,
                })
                .collect(),
            domain: VolitionDomain::L1,
        })
        .unwrap()
        .data,
    )
}

pub fn declared_class(tag: i32) -> StateDiffsResponse {
    let sd = state_diff(tag).state_diff;
    let (class_hash, compiled_class_hash) = sd
        .declared_sierra_classes
        .into_iter()
        .map(|(s, c)| (Hash(s.0), Some(Hash(c.0))))
        .chain(
            sd.declared_cairo_classes
                .into_iter()
                .map(|c| (Hash(c.0), None)),
        )
        .next()
        .unwrap();

    StateDiffsResponse::DeclaredClass(
        Tagged::get(format!("declared class {tag}"), || DeclaredClass {
            class_hash,
            compiled_class_hash,
        })
        .unwrap()
        .data,
    )
}

pub fn state_diff(tag: i32) -> UnverifiedStateUpdateData {
    let (declared_cairo_classes, declared_sierra_classes) = match Faker.fake::<Option<CasmHash>>() {
        Some(x) => ([].into(), [(SierraHash(Faker.fake()), x)].into()),
        None => ([ClassHash(Faker.fake())].into(), [].into()),
    };
    let (contract_updates, system_contract_updates) = if Faker.fake() {
        (
            [(
                Faker.fake(),
                ContractUpdate {
                    storage: Faker.fake(),
                    class: Some(ContractClassUpdate::Deploy(Faker.fake())),
                    nonce: Faker.fake(),
                },
            )]
            .into(),
            [].into(),
        )
    } else {
        ([].into(), [(ContractAddress::ONE, Faker.fake())].into())
    };
    Tagged::get(format!("state diff {tag}"), || UnverifiedStateUpdateData {
        expected_commitment: Default::default(),
        state_diff: StateUpdateData {
            contract_updates,
            system_contract_updates,
            declared_cairo_classes,
            declared_sierra_classes,
        },
    })
    .unwrap()
    .data
}

pub fn len(tag: i32) -> usize {
    state_diff(tag).state_diff.state_diff_length()
}

pub fn surplus_storage() -> StateDiffsResponse {
    StateDiffsResponse::ContractDiff(ContractDiff {
        address: Faker.fake(),
        nonce: None,
        class_hash: None,
        values: vec![Faker.fake()], // Must not be empty
        domain: Faker.fake(),
    })
}

pub fn surplus_nonce() -> StateDiffsResponse {
    StateDiffsResponse::ContractDiff(ContractDiff {
        address: Faker.fake(),
        nonce: Some(Faker.fake()),
        class_hash: None,
        values: vec![],
        domain: Faker.fake(),
    })
}

pub fn surplus_class() -> StateDiffsResponse {
    StateDiffsResponse::ContractDiff(ContractDiff {
        address: Faker.fake(),
        nonce: None,
        class_hash: Some(Faker.fake()),
        values: vec![],
        domain: Faker.fake(),
    })
}
