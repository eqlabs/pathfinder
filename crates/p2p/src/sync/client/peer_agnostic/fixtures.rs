use std::collections::VecDeque;
use std::sync::Arc;

use fake::{Dummy, Fake, Faker};
use futures::channel::mpsc;
use futures::SinkExt;
use libp2p::PeerId;
use p2p_proto::class::Class;
use p2p_proto::common::{Address, Hash, VolitionDomain};
use p2p_proto::sync::class::ClassesResponse;
use p2p_proto::sync::event::EventsResponse;
use p2p_proto::sync::header::BlockHeadersResponse;
use p2p_proto::sync::state::{
    ContractDiff,
    ContractStoredValue,
    DeclaredClass,
    StateDiffsResponse,
};
use p2p_proto::sync::transaction::{TransactionWithReceipt, TransactionsResponse};
use pathfinder_common::event::Event;
use pathfinder_common::prelude::*;
use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdate, StateUpdateData};
use pathfinder_common::transaction::{
    DeployAccountTransactionV1,
    DeployAccountTransactionV3,
    DeployTransactionV0,
    DeployTransactionV1,
    TransactionVariant,
};
use pathfinder_tagged::Tagged;
use pathfinder_tagged_debug_derive::TaggedDebug;
use rand::seq::SliceRandom;
use tokio::sync::Mutex;

use super::ClassDefinition;
use crate::sync::client::conv::{CairoDefinition, SierraDefinition, ToDto, TryFromDto};
use crate::sync::client::peer_agnostic::Receipt;

#[derive(Clone, PartialEq, TaggedDebug)]
pub struct TestPeer(pub PeerId);

#[derive(Clone, PartialEq, TaggedDebug)]
pub struct TestTxn {
    pub t: TransactionVariant,
    pub r: Receipt,
}

/// We want to simulate transactions as they're incoming via P2P, where
/// contract_address for deploy and deploy account transactions is not
/// propagated.
impl<T> Dummy<T> for TestTxn {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        let mut t = Faker.fake_with_rng(rng);
        match &mut t {
            TransactionVariant::DeployV0(DeployTransactionV0 {
                contract_address, ..
            })
            | TransactionVariant::DeployV1(DeployTransactionV1 {
                contract_address, ..
            })
            | TransactionVariant::DeployAccountV1(DeployAccountTransactionV1 {
                contract_address,
                ..
            })
            | TransactionVariant::DeployAccountV3(DeployAccountTransactionV3 {
                contract_address,
                ..
            }) => {
                *contract_address = ContractAddress::ZERO;
            }
            _ => {}
        };
        Self {
            t,
            r: Faker.fake_with_rng(rng),
        }
    }
}

#[derive(Copy, Clone, Dummy, PartialEq, TaggedDebug)]
pub struct TaggedTransactionHash(pub TransactionHash);

pub type TaggedEventsForBlockByTransaction =
    (BlockNumber, Vec<(TaggedTransactionHash, Vec<Event>)>);

impl TestTxn {
    pub fn new((t, r): (TransactionVariant, Receipt)) -> Self {
        Self { t, r }
    }
}

pub fn peer(tag: i32) -> TestPeer {
    pathfinder_tagged::init();
    Tagged::<TestPeer>::get(format!("peer {tag}"), || TestPeer(PeerId::random()))
        .unwrap()
        .data
}

#[allow(clippy::type_complexity)]
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

#[allow(clippy::type_complexity)]
pub async fn send_request<T>(
    responses: Arc<Mutex<VecDeque<Result<Vec<T>, TestPeer>>>>,
) -> anyhow::Result<mpsc::Receiver<std::io::Result<T>>> {
    let mut guard = responses.lock().await;
    match guard.pop_front() {
        Some(Ok(responses)) => {
            let (mut tx, rx) = mpsc::channel(responses.len() + 1);
            for r in responses {
                tx.send(Ok(r)).await.unwrap();
            }
            Ok(rx)
        }
        Some(Err(_)) => Err(anyhow::anyhow!("peer failed")),
        None => {
            panic!("fix your assumed responses")
        }
    }
}

pub fn hdr_resp(tag: i32) -> BlockHeadersResponse {
    let h = hdr(tag);
    BlockHeadersResponse::Header(Box::new(h.to_dto()))
}

pub fn hdr(tag: i32) -> SignedBlockHeader {
    Tagged::get(format!("header {tag}"), || SignedBlockHeader {
        header: BlockHeader {
            number: BlockNumber::new_or_panic(tag as u64),
            ..Faker.fake()
        },
        ..Faker.fake()
    })
    .unwrap()
    .data
}

pub fn txn_resp(tag: i32, transaction_index: u64) -> TransactionsResponse {
    let TestTxn { t, r } = txn(tag, transaction_index);
    let receipt = (&t, r).to_dto();
    let h = t.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
    let transaction = p2p_proto::sync::transaction::Transaction {
        txn: t.to_dto(),
        transaction_hash: Hash(h.0),
    };
    let resp = TransactionsResponse::TransactionWithReceipt(TransactionWithReceipt {
        receipt,
        transaction,
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
    let sd = state_diff(tag);
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
    let sd = state_diff(tag);
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

pub fn state_diff(tag: i32) -> StateUpdateData {
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
        (
            [].into(),
            [(
                *ContractAddress::SYSTEM
                    .choose(&mut rand::thread_rng())
                    .unwrap(),
                Faker.fake(),
            )]
            .into(),
        )
    };

    Tagged::get(format!("state diff {tag}"), || StateUpdateData {
        contract_updates,
        system_contract_updates,
        declared_cairo_classes,
        declared_sierra_classes,
        migrated_compiled_classes: Default::default(),
    })
    .unwrap()
    .data
}

pub fn len(tag: i32) -> usize {
    state_diff(tag)
        .state_diff_length()
        .try_into()
        .expect("ptr size is 64 bits")
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

pub fn class_resp(tag: i32) -> ClassesResponse {
    use pathfinder_common::class_definition::ClassDefinition;
    let c = Tagged::<Class>::get(format!("class response {tag}"), || {
        let c = Faker.fake::<ClassDefinition<'_>>();
        match c {
            ClassDefinition::Sierra(s) => Class::Cairo1 {
                class: s.to_dto(),
                domain: 0,
                class_hash: Faker.fake(),
            },
            ClassDefinition::Cairo(c) => Class::Cairo0 {
                class: c.to_dto(),
                domain: 0,
                class_hash: Faker.fake(),
            },
        }
    })
    .unwrap()
    .data;
    ClassesResponse::Class(c)
}

pub fn class(tag: i32, block_number: u64) -> ClassDefinition {
    let block_number = BlockNumber::new_or_panic(block_number);
    match class_resp(tag) {
        ClassesResponse::Class(Class::Cairo0 {
            class,
            domain: _,
            class_hash,
        }) => {
            Tagged::get(format!("class {tag}"), || ClassDefinition::Cairo {
                block_number,
                definition: CairoDefinition::try_from_dto(class).unwrap().0,
                hash: ClassHash(class_hash.0),
            })
            .unwrap()
            .data
        }
        ClassesResponse::Class(Class::Cairo1 {
            class,
            domain: _,
            class_hash,
        }) => {
            Tagged::get(format!("class {tag}"), || ClassDefinition::Sierra {
                block_number,
                sierra_definition: SierraDefinition::try_from_dto(class).unwrap().0,
                hash: SierraHash(class_hash.0),
            })
            .unwrap()
            .data
        }
        ClassesResponse::Fin => unreachable!(),
    }
}

pub fn event_resp(ev: i32, txn: i32) -> EventsResponse {
    let (_, mut v) = events(vec![(vec![ev], txn)], 0);
    let t = v[0].0;
    let e = v.pop().unwrap().1.pop().unwrap();

    let e = p2p_proto::sync::event::Event {
        transaction_hash: Hash(t.0 .0),
        from_address: e.from_address.0,
        keys: e.keys.iter().map(|x| x.0).collect(),
        data: e.data.iter().map(|x| x.0).collect(),
    };

    EventsResponse::Event(
        Tagged::<p2p_proto::sync::event::Event>::get(
            format!("event response {ev}, txn {txn}"),
            || e,
        )
        .unwrap()
        .data,
    )
}

pub fn events(
    events_by_txn: Vec<(Vec<i32>, i32)>,
    block: u64,
) -> TaggedEventsForBlockByTransaction {
    let events_by_txn = events_by_txn
        .into_iter()
        .map(|(evs, txn)| {
            let evs = evs
                .into_iter()
                .map(|ev| Tagged::get_fake(format!("event {ev}")).unwrap().data)
                .collect();
            let t = Tagged::<TaggedTransactionHash>::get_fake(format!("txn hash {txn}"))
                .unwrap()
                .data;
            (t, evs)
        })
        .collect();
    (BlockNumber::new_or_panic(block), events_by_txn)
}
