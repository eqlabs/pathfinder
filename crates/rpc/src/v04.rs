use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

pub mod method;
pub(crate) mod types;

use crate::v02::method as v02_method;
use crate::v03::method as v03_method;
use crate::v04::method as v04_method;
