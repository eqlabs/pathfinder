pub use malachite_types::VoteType;
use malachite_types::{
    Height as MalachiteHeight, NilOrVal, Round as MalachiteRound, SignedExtension
};
use p2p_proto::consensus as p2p_proto;
use serde::{Deserialize, Serialize};

use super::{ConsensusBounded, ConsensusValue, Height, MalachiteContext, Round, ValidatorAddress};

/// A vote for a value in a consensus round.
///
/// A vote is cast by a validator to indicate their agreement or disagreement
/// with a proposed block value. The vote includes the validator's address, the
/// round number, and the block value being voted on.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote<V> {
    pub r#type: VoteType,
    pub height: Height,
    pub round: Round,
    pub value: Option<ConsensusValue<V>>,
    pub validator_address: ValidatorAddress,
    //pub extension: Option<SignedExtension<MalachiteContext<V>>>,
}

impl<V: ConsensusBounded + 'static> std::fmt::Debug for Vote<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value_str = match &self.value {
            None => "Nil".to_string(),
            Some(val) => format!("{:?}", val),
        };
        write!(
            f,
            "H:{} R:{} From:{} Val:{}",
            self.height, self.round, self.validator_address, value_str
        )
    }
}

impl<V: ConsensusBounded + 'static> serde::Serialize for Vote<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Create a simple struct for serialization
        #[derive(Serialize)]
        struct VoteHelper<'a, V: ConsensusBounded + 'static> {
            #[serde(rename = "type")]
            vote_type: &'static str,
            height: &'a Height,
            round: &'a Round,
            value: Option<&'a ConsensusValue<V>>,
            validator_address: &'a ValidatorAddress,
            //extension: Option<ExtensionHelper>,
        }

        /*#[derive(Serialize)]
        struct ExtensionHelper {
            message: String,
            signature: String,
        }*/

        let vote_type = match self.r#type {
            VoteType::Prevote => "prevote",
            VoteType::Precommit => "precommit",
        };

        let value = match &self.value {
            None => None,
            Some(val) => Some(val),
        };

        /*let extension = self.extension.as_ref().map(|ext| ExtensionHelper {
            message: base64::encode(&ext.message),
            signature: base64::encode(ext.signature.to_bytes()),
        });*/

        let helper = VoteHelper {
            vote_type,
            height: &self.height,
            round: &self.round,
            value,
            validator_address: &self.validator_address,
            //extension,
        };

        helper.serialize(serializer)
    }
}

impl<'de, V: ConsensusBounded + 'static> serde::Deserialize<'de> for Vote<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Helper struct for deserialization
        #[derive(Deserialize)]
        struct VoteHelper<V> {
            #[serde(rename = "type")]
            vote_type: String,
            height: Height,
            round: Round,
            value: Option<ConsensusValue<V>>,
            validator_address: ValidatorAddress,
            //extension: Option<ExtensionHelper>,
        }

        /*#[derive(Deserialize)]
        struct ExtensionHelper {
            message: String,
            signature: String,
        }*/

        let helper = VoteHelper::deserialize(deserializer)?;

        let vote_type = match helper.vote_type.as_str() {
            "prevote" => VoteType::Prevote,
            "precommit" => VoteType::Precommit,
            _ => {
                return Err(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(&helper.vote_type),
                    &"prevote or precommit",
                ))
            }
        };

        let value = match helper.value {
            None => None,
            Some(val) => Some(val),
        };

        /*let extension = helper
            .extension
            .map(|ext_helper| {
                let message = base64::decode(&ext_helper.message).map_err(|e| {
                    serde::de::Error::custom(format!("Invalid base64 message: {e}"))
                })?;
                let signature_bytes = base64::decode(&ext_helper.signature).map_err(|e| {
                    serde::de::Error::custom(format!("Invalid base64 signature: {e}"))
                })?;

                if signature_bytes.len() != 64 {
                    return Err(serde::de::Error::custom("Signature must be 64 bytes"));
                }

                let mut signature_array = [0u8; 64];
                signature_array.copy_from_slice(&signature_bytes);

                Ok(SignedExtension {
                    message,
                    signature: malachite_signing_ed25519::Signature::from_bytes(signature_array),
                })
            })
            .transpose()?;*/

        Ok(Vote {
            r#type: vote_type,
            height: helper.height,
            round: helper.round,
            value,
            validator_address: helper.validator_address,
            //extension,
        })
    }
}

impl<V: ConsensusBounded + 'static> malachite_types::Vote<MalachiteContext<V>> for Vote<V> {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> MalachiteRound {
        self.round.into_inner()
    }

    fn value(&self) -> &NilOrVal<V> {
        match &self.value {
            None => &NilOrVal::Nil,
            Some(val) => &NilOrVal::Val(val.value),
        }
    }

    fn take_value(self) -> NilOrVal<V> {
        match self.value {
            None => NilOrVal::Nil,
            Some(val) => NilOrVal::Val(val.value),
        }
    }

    fn vote_type(&self) -> VoteType {
        self.r#type
    }

    fn validator_address(&self) -> &ValidatorAddress {
        &self.validator_address
    }

    fn extension(&self) -> Option<&SignedExtension<MalachiteContext<V>>> {
        None
    }

    fn take_extension(&mut self) -> Option<SignedExtension<MalachiteContext<V>>> {
        None
    }

    fn extend(self, extension: SignedExtension<MalachiteContext<V>>) -> Self {
        Self {
            //extension: Some(extension),
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use ::p2p_proto::common::{Address, Hash};
    use pathfinder_crypto::Felt;

    use super::*;

    #[test]
    fn test_vote_serialization_roundtrip() {
        // Create a test vote
        let vote = Vote {
            r#type: VoteType::Prevote,
            height: Height::try_from(100).expect("block number out of range"),
            round: Round::from(5),
            value: NilOrVal::Val(Hash(Felt::from_hex_str("0x123456789").unwrap())),
            validator_address: ValidatorAddress::from(Address(
                Felt::from_hex_str("0xabcdef").unwrap(),
            )),
            extension: Some(SignedExtension {
                message: vec![1, 2, 3, 4, 5],
                signature: malachite_signing_ed25519::Signature::from_bytes([
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                    43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
                    63, 64,
                ]),
            }),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&vote).expect("Failed to serialize vote");
        println!("Serialized vote: {json}");

        // Deserialize from JSON
        let deserialized_vote: Vote =
            serde_json::from_str(&json).expect("Failed to deserialize vote");

        // Verify the roundtrip
        assert_eq!(vote.r#type, deserialized_vote.r#type);
        assert_eq!(vote.height, deserialized_vote.height);
        assert_eq!(vote.round, deserialized_vote.round);
        assert_eq!(vote.value, deserialized_vote.value);
        assert_eq!(vote.validator_address, deserialized_vote.validator_address);
        assert_eq!(
            vote.extension.as_ref().map(|e| &e.message),
            deserialized_vote.extension.as_ref().map(|e| &e.message)
        );
        assert_eq!(
            vote.extension.as_ref().map(|e| e.signature.to_bytes()),
            deserialized_vote
                .extension
                .as_ref()
                .map(|e| e.signature.to_bytes())
        );
    }

    #[test]
    fn test_vote_serialization_with_nil_value() {
        // Create a test vote with Nil value
        let vote = Vote {
            r#type: VoteType::Precommit,
            height: Height::try_from(101).expect("block number out of range"),
            round: Round::from(6),
            value: NilOrVal::Nil,
            validator_address: ValidatorAddress::from(Address(
                Felt::from_hex_str("0xdef").unwrap(),
            )),
            extension: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&vote).expect("Failed to serialize vote");
        println!("Serialized vote with nil value: {json}");

        // Deserialize from JSON
        let deserialized_vote: Vote =
            serde_json::from_str(&json).expect("Failed to deserialize vote");

        // Verify the roundtrip
        assert_eq!(vote.r#type, deserialized_vote.r#type);
        assert_eq!(vote.height, deserialized_vote.height);
        assert_eq!(vote.round, deserialized_vote.round);
        assert_eq!(vote.value, deserialized_vote.value);
        assert_eq!(vote.validator_address, deserialized_vote.validator_address);
        assert_eq!(vote.extension, deserialized_vote.extension);
    }
}



/* ------------------ */


impl<V: ConsensusBounded + 'static> From<p2p_proto::Vote> for Vote<V> {
    fn from(vote: p2p_proto::Vote) -> Self {
        Self {
            r#type: match vote.vote_type {
                p2p_proto::VoteType::Prevote => VoteType::Prevote,
                p2p_proto::VoteType::Precommit => VoteType::Precommit,
            },
            height: Height::try_from(vote.height).expect("block number out of range"),
            round: Round::from(vote.round),
            value: match vote.block_hash {
                Some(v) => Some(ConsensusValue::new(v)),
                None => None,
            },
            validator_address: ValidatorAddress::from(vote.voter),
            extension: None, // TODO: implement extension
        }
    }
}

impl<V: ConsensusBounded + 'static> From<Vote<V>> for p2p_proto::Vote {
    fn from(vote: Vote<V>) -> Self {
        p2p_proto::Vote {
            vote_type: match vote.r#type {
                VoteType::Prevote => p2p_proto::VoteType::Prevote,
                VoteType::Precommit => p2p_proto::VoteType::Precommit,
            },
            height: vote.height.as_u64(),
            round: vote.round.as_u32().expect("round is not nil"),
            block_hash: match &vote.value {
                Some(value) => Some(value.value.clone()),
                None => None,
            },
            voter: vote.validator_address.into(),
            extension: vote.extension.map(|ext| ext.message.clone()),
        }
    }
}
