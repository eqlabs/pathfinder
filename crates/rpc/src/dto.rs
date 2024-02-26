mod event;
mod header;
mod primitives;
mod receipt;

pub mod serialize;

pub use event::*;
pub use header::*;
pub use primitives::*;
pub use receipt::*;

#[cfg(test)]
/// Merges two json objects together. Panics if either of them is not an object.
fn merge_json(mut x: serde_json::Value, y: serde_json::Value) -> serde_json::Value {
    let Some(x_obj) = x.as_object_mut() else {
        panic!("x was not an object");
    };

    let serde_json::Value::Object(y) = y else {
        panic!("y was not an object");
    };

    for (k, v) in y {
        if x_obj.insert(k.clone(), v).is_some() {
            panic!("{k} already has a value");
        }
    }

    x
}
