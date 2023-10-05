use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

pub mod method;

use crate::v04::method as v04_method;

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder("v0.5")
        .register("starknet_addDeclareTransaction"           , v04_method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction"     , v04_method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction"            , v04_method::add_invoke_transaction)
        .register("starknet_specVersion"                     , method::spec_version)
}
