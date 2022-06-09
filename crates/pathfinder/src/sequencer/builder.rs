#![allow(dead_code)]

use std::marker::PhantomData;

use crate::{
    core::{
        ClassHash, ContractAddress, StarknetBlockHash, StarknetBlockNumber,
        StarknetTransactionHash, StorageAddress,
    },
    sequencer::error::SequencerError,
};

pub struct Request<'a, S: RequestState> {
    marker: PhantomData<S>,
    url: reqwest::Url,
    client: &'a reqwest::Client,
}

pub struct Start;
pub struct WithUrl;
pub struct WithGateWay;
pub struct WithMethod;

pub enum BlockId {
    Number(StarknetBlockNumber),
    Hash(StarknetBlockHash),
    Latest,
    Pending,
}

impl BlockId {
    fn to_str(&self) -> std::borrow::Cow<'static, str> {
        use std::borrow::Cow;

        match self {
            BlockId::Number(number) => Cow::from(number.0.to_string()),
            BlockId::Hash(hash) => hash.0.to_hex_str(),
            BlockId::Latest => Cow::from("latest"),
            BlockId::Pending => Cow::from("pending"),
        }
    }
}

impl<'a> Request<'a, Start> {
    pub fn new(client: &'a reqwest::Client, url: reqwest::Url) -> Request<'a, WithUrl> {
        Request {
            url,
            client,
            marker: PhantomData::default(),
        }
    }
}

impl<'a> Request<'a, WithUrl> {
    pub fn gateway(self) -> Request<'a, WithGateWay> {
        self.with_gateway("gateway")
    }

    pub fn feeder_gateway(self) -> Request<'a, WithGateWay> {
        self.with_gateway("feeder_gateway")
    }

    fn with_gateway(mut self, gateway: &str) -> Request<'a, WithGateWay> {
        self.url
            .path_segments_mut()
            .expect("Base URL is valid")
            .push(gateway);
        Request {
            url: self.url,
            client: self.client,
            marker: PhantomData::default(),
        }
    }
}

impl<'a> Request<'a, WithGateWay> {
    pub fn add_transaction(self) -> Request<'a, WithMethod> {
        self.with_method("add_transaction")
    }

    pub fn call_contract(self) -> Request<'a, WithMethod> {
        self.with_method("call_contract")
    }

    pub fn get_block(self) -> Request<'a, WithMethod> {
        self.with_method("get_block")
    }

    pub fn get_full_contract(self) -> Request<'a, WithMethod> {
        self.with_method("get_full_contract")
    }

    pub fn get_class_by_hash(self) -> Request<'a, WithMethod> {
        self.with_method("get_class_by_hash")
    }

    pub fn get_class_hash_at(self) -> Request<'a, WithMethod> {
        self.with_method("get_class_hash_at")
    }

    pub fn get_storage_at(self) -> Request<'a, WithMethod> {
        self.with_method("get_storage_at")
    }

    pub fn get_transaction(self) -> Request<'a, WithMethod> {
        self.with_method("get_transaction")
    }

    pub fn get_transaction_status(self) -> Request<'a, WithMethod> {
        self.with_method("get_transaction_status")
    }

    pub fn get_state_update(self) -> Request<'a, WithMethod> {
        self.with_method("get_state_update")
    }

    pub fn get_contract_addresses(self) -> Request<'a, WithMethod> {
        self.with_method("get_contract_addresses")
    }

    #[cfg(test)]
    pub fn custom(self, method: &'static str) -> Request<'a, WithMethod> {
        self.with_method(method)
    }

    fn with_method(mut self, method: &str) -> Request<'a, WithMethod> {
        self.url
            .path_segments_mut()
            .expect("Base URL is valid")
            .push(method);

        Request {
            url: self.url,
            client: self.client,
            marker: PhantomData::default(),
        }
    }
}

impl<'a> Request<'a, WithMethod> {
    pub fn at_block<B: Into<BlockId>>(self, block: B) -> Self {
        use std::borrow::Cow;

        let block: BlockId = block.into();
        let (name, value) = match block {
            BlockId::Number(number) => ("blockNumber", Cow::from(number.0.to_string())),
            BlockId::Hash(hash) => ("blockHash", hash.0.to_hex_str()),
            // The name for these two could be either "blockNumber" or "blockHash".
            BlockId::Latest => ("blockNumber", Cow::from("latest")),
            BlockId::Pending => ("blockNumber", Cow::from("pending")),
        };

        self.add_param(name, &value)
    }

    pub fn with_contract_address(self, address: ContractAddress) -> Self {
        self.add_param("contractAddress", &address.0.to_hex_str())
    }

    pub fn with_class_hash(self, class_hash: ClassHash) -> Self {
        self.add_param("classHash", &class_hash.0.to_hex_str())
    }

    pub fn with_optional_token(self, token: Option<&str>) -> Self {
        match token {
            Some(token) => self.add_param("token", token),
            None => self,
        }
    }

    pub fn with_storage_address(self, address: StorageAddress) -> Self {
        use crate::rpc::serde::starkhash_to_dec_str;
        self.add_param("key", &starkhash_to_dec_str(&address.0))
    }

    pub fn with_transaction_hash(self, hash: StarknetTransactionHash) -> Self {
        self.add_param("transactionHash", &hash.0.to_hex_str())
    }

    pub fn add_param(mut self, name: &str, value: &str) -> Self {
        self.url.query_pairs_mut().append_pair(name, value);
        self
    }

    pub fn finalize(self) -> reqwest::Url {
        self.url
    }

    pub async fn get(self) -> Result<reqwest::Response, SequencerError> {
        let response = self.client.get(self.url).send().await?;
        Ok(response)
    }

    pub async fn post_json<T>(self, json: &T) -> Result<reqwest::Response, SequencerError>
    where
        T: serde::Serialize + ?Sized,
    {
        let response = self.client.post(self.url).json(json).send().await?;
        Ok(response)
    }
}

pub trait RequestState {}
impl RequestState for Start {}
impl RequestState for WithUrl {}
impl RequestState for WithGateWay {}
impl RequestState for WithMethod {}

impl From<crate::rpc::types::BlockNumberOrTag> for BlockId {
    fn from(block: crate::rpc::types::BlockNumberOrTag) -> Self {
        use crate::rpc::types::BlockNumberOrTag::*;
        use crate::rpc::types::Tag::*;

        match block {
            Number(number) => Self::Number(number),
            Tag(Latest) => Self::Latest,
            Tag(Pending) => Self::Pending,
        }
    }
}

impl From<crate::rpc::types::BlockHashOrTag> for BlockId {
    fn from(block: crate::rpc::types::BlockHashOrTag) -> Self {
        use crate::rpc::types::BlockHashOrTag::*;
        use crate::rpc::types::Tag::*;

        match block {
            Hash(hash) => Self::Hash(hash),
            Tag(Latest) => Self::Latest,
            Tag(Pending) => Self::Pending,
        }
    }
}
