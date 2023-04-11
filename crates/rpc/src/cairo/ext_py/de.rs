//! The json deserializable types

use super::{types::TransactionSimulation, CallFailure, SubprocessError};
use crate::v02::types::reply::FeeEstimate;
use pathfinder_common::CallResultValue;

/// The python loop currently responds with these four possibilities. An enum would be more
/// appropriate.
///
/// This is [`ChildResponse::refine`]'d into [`RefinedChildResponse`]
#[derive(serde::Deserialize, Debug)]
pub(crate) struct ChildResponse<'a> {
    /// Describes the outcome with three alternatives (good, known error, unknown error)
    status: Status,
    /// Head of the raw exception message limited to 197 first characters and an three dots for
    /// longer. Probably okay to give as a hint in the internal error message.
    #[serde(borrow)]
    exception: Option<std::borrow::Cow<'a, str>>,
    /// Enumeration of "known errors", present when `status` is [`Status::Error`].
    kind: Option<ErrorKind>,
    /// The real output from the contract when `status` is [`Status::Ok`].
    #[serde(default)]
    output: Option<OutputValue>,
}

/// Deserializes either the call output value or the fee estimate.
#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum OutputValue {
    Call(Vec<CallResultValue>),
    Fee(Vec<FeeEstimate>),
    Traces(Vec<TransactionSimulation>),
}

impl<'a> ChildResponse<'a> {
    pub(super) fn refine(mut self) -> Result<RefinedChildResponse<'a>, SubprocessError> {
        match (&self.status, &mut self.kind, &mut self.exception) {
            (Status::Ok, None, None) => Ok(RefinedChildResponse {
                status: RefinedStatus::Ok(self.output.ok_or(SubprocessError::InvalidResponse)?),
            }),
            (Status::Error, x @ Some(_), None) => Ok(RefinedChildResponse {
                status: RefinedStatus::Error(x.take().unwrap()),
            }),
            (Status::Failed, None, s @ &mut Some(_)) => Ok(RefinedChildResponse {
                status: RefinedStatus::Failed(s.take().unwrap()),
            }),
            // these should not happen, so turn them into similar as serde_json errors
            _ => Err(SubprocessError::InvalidResponse),
        }
    }
}

impl RefinedChildResponse<'_> {
    pub(super) fn into_messages(self) -> (Status, Result<OutputValue, CallFailure>) {
        match self {
            RefinedChildResponse {
                status: RefinedStatus::Ok(x),
            } => (Status::Ok, Ok(x)),
            RefinedChildResponse {
                status: RefinedStatus::Error(e),
            } => (Status::Error, Err(CallFailure::from(e))),
            RefinedChildResponse {
                status: RefinedStatus::Failed(s),
            } => (
                Status::Failed,
                Err(CallFailure::ExecutionFailed(s.to_string())),
            ),
        }
    }
}

/// Different kinds of errors the python side recognizes.
#[derive(serde::Deserialize, Debug)]
pub enum ErrorKind {
    #[serde(rename = "NO_SUCH_BLOCK")]
    NoSuchBlock,
    #[serde(rename = "NO_SUCH_CONTRACT")]
    NoSuchContract,
    #[serde(rename = "INVALID_SCHEMA_VERSION")]
    InvalidSchemaVersion,
    #[serde(rename = "INVALID_INPUT")]
    InvalidCommand,
    #[serde(rename = "INVALID_ENTRY_POINT")]
    InvalidEntryPoint,
}

#[derive(serde::Deserialize, PartialEq, Eq, Debug)]
pub enum Status {
    /// No errors
    #[serde(rename = "ok")]
    Ok,
    /// Known error happened
    #[serde(rename = "error")]
    Error,
    /// Any of the cairo-lang errors happened
    #[serde(rename = "failed")]
    Failed,
}

/// The format we'd prefer to process instead of [`ChildResponse`].
pub(super) struct RefinedChildResponse<'a> {
    status: RefinedStatus<'a>,
}

/// More sensible alternative to [`Status`].
pub(super) enum RefinedStatus<'a> {
    Ok(OutputValue),
    Error(ErrorKind),
    Failed(std::borrow::Cow<'a, str>),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: https://github.com/eqlabs/pathfinder/issues/1018
    #[test]
    fn test_parse_tx_traces() {
        let json = r###"
        [
            {
              "fee_estimation": {
                "gas_consumed": "0x1365",
                "gas_price": "0x598ec8f684",
                "overall_fee": "0x6c8ee3f950e14"
              },
              "trace": {
                "function_invocation": {
                  "messages": [],
                  "caller_address": "0x0",
                  "events": [],
                  "class_hash": "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
                  "internal_calls": [
                    {
                      "messages": [],
                      "caller_address": "0x0",
                      "events": [
                        {
                          "order": 1,
                          "keys": [
                            "0x5ad857f66a5b55f1301ff1ed7e098ac6d4433148f0b72ebc4a2945ab85ad53"
                          ],
                          "data": [
                            "0x4705945f0a755c6ca0df850d274f2cf55872e1ce6cb3c26d992a3f5c8680d2e",
                            "0x1",
                            "0x1"
                          ]
                        }
                      ],
                      "class_hash": "0x33434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2",
                      "internal_calls": [
                        {
                          "messages": [],
                          "caller_address": "0x398e624a0f1d7d45050e3ddeee9f79604a7a6929d651ed4b01bc64cdfafc6af",
                          "events": [],
                          "class_hash": "0xd0e183745e9dae3e4e78a8ffedcce0903fc4900beace4e0abf192d4c202da3",
                          "internal_calls": [
                            {
                              "messages": [],
                              "caller_address": "0x398e624a0f1d7d45050e3ddeee9f79604a7a6929d651ed4b01bc64cdfafc6af",
                              "events": [
                                {
                                  "order": 0,
                                  "keys": [
                                    "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
                                  ],
                                  "data": [
                                    "0x398e624a0f1d7d45050e3ddeee9f79604a7a6929d651ed4b01bc64cdfafc6af",
                                    "0x13894c2403b65bc92804020e483ad34e6460a57ceb53b3133bdfd07923258c7",
                                    "0xb1a2bc2ec50000",
                                    "0x0"
                                  ]
                                }
                              ],
                              "class_hash": "0x2760f25d5a4fb2bdde5f561fd0b44a3dee78c28903577d37d669939d97036a0",
                              "internal_calls": [],
                              "contract_address": "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                              "execution_resources": {
                                "n_memory_holes": 42,
                                "n_steps": 526,
                                "builtin_instance_counter": {
                                  "pedersen_builtin": 4,
                                  "range_check_builtin": 21
                                }
                              },
                              "call_type": "DELEGATE",
                              "entry_point_type": "EXTERNAL",
                              "selector": "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                              "calldata": [
                                "0x13894c2403b65bc92804020e483ad34e6460a57ceb53b3133bdfd07923258c7",
                                "0xb1a2bc2ec50000",
                                "0x0"
                              ],
                              "result": [
                                "0x1"
                              ]
                            }
                          ],
                          "contract_address": "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                          "execution_resources": {
                            "n_memory_holes": 42,
                            "n_steps": 586,
                            "builtin_instance_counter": {
                              "pedersen_builtin": 4,
                              "range_check_builtin": 21
                            }
                          },
                          "call_type": "CALL",
                          "entry_point_type": "EXTERNAL",
                          "selector": "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                          "calldata": [
                            "0x13894c2403b65bc92804020e483ad34e6460a57ceb53b3133bdfd07923258c7",
                            "0xb1a2bc2ec50000",
                            "0x0"
                          ],
                          "result": [
                            "0x1"
                          ]
                        }
                      ],
                      "contract_address": "0x398e624a0f1d7d45050e3ddeee9f79604a7a6929d651ed4b01bc64cdfafc6af",
                      "execution_resources": {
                        "n_memory_holes": 45,
                        "n_steps": 805,
                        "builtin_instance_counter": {
                          "pedersen_builtin": 4,
                          "range_check_builtin": 24
                        }
                      },
                      "call_type": "DELEGATE",
                      "entry_point_type": "EXTERNAL",
                      "selector": "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
                      "calldata": [
                        "0x1",
                        "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                        "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                        "0x0",
                        "0x3",
                        "0x3",
                        "0x13894c2403b65bc92804020e483ad34e6460a57ceb53b3133bdfd07923258c7",
                        "0xb1a2bc2ec50000",
                        "0x0"
                      ],
                      "result": [
                        "0x1"
                      ]
                    }
                  ],
                  "contract_address": "0x398e624a0f1d7d45050e3ddeee9f79604a7a6929d651ed4b01bc64cdfafc6af",
                  "execution_resources": {
                    "n_memory_holes": 45,
                    "n_steps": 865,
                    "builtin_instance_counter": {
                      "pedersen_builtin": 4,
                      "range_check_builtin": 24
                    }
                  },
                  "call_type": "CALL",
                  "entry_point_type": "EXTERNAL",
                  "selector": "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
                  "calldata": [
                    "0x1",
                    "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                    "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                    "0x0",
                    "0x3",
                    "0x3",
                    "0x13894c2403b65bc92804020e483ad34e6460a57ceb53b3133bdfd07923258c7",
                    "0xb1a2bc2ec50000",
                    "0x0"
                  ],
                  "result": [
                    "0x1"
                  ]
                },
                "signature": [
                  "0x7b91e638a4ff65401caa8dccc1db4c3577a4903bb492134951a98e4aeec2694",
                  "0x14ae9bca705396e80ac11db763b04f99744aa5423728cc1d8b633641d240959",
                  "0x724bd33f5e52ac0a0f53d277ba26b7270131d968a9ff4fe26a00007d1f2ea22",
                  "0x664e5ffb985db8cc34d66dc97602b4e81fbfbe81eda833d600b536a3d438ead"
                ]
              }
            }
          ]          
        "###;

        let output: OutputValue = serde_json::from_str(json).unwrap();
        assert_matches::assert_matches!(output, OutputValue::Traces(_));
    }
}
