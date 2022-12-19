use anyhow::Context;
use stark_hash::{stark_hash, Felt};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    let myself = args
        .next()
        .unwrap_or_else(|| String::from("compute_contract_state_hash"));

    let args = args
        .map(|x| Felt::from_hex_str(&x).map(Some))
        .chain(std::iter::repeat_with(|| Ok(None)));

    let mut description = String::with_capacity(1 + 64 + 64 + 64 + 64 + 4);
    description.push('#');

    let res = args
        .enumerate()
        // was thinking this would be like a column value so start from 1
        .map(|(nth, x)| (nth + 1, x))
        // build the description up with an inspect
        .inspect(|(_, x)| {
            use std::fmt::Write;
            if let Ok(x) = x {
                write!(description, " {:x}", x.unwrap_or(Felt::ZERO)).unwrap();
            }
        })
        .take(4)
        .try_fold(None, |acc, next| {
            let nth = next.0 + 1;
            let next = next
                .1
                .with_context(|| format!("Failed to parse {nth} parameter"))?;
            let next = if nth < 2 {
                next.with_context(|| format!("Missing {nth} parameter"))?
            } else {
                next.unwrap_or(Felt::ZERO)
            };
            Ok::<_, anyhow::Error>(acc.map(|prev| stark_hash(prev, next)).or(Some(next)))
        })
        .with_context(|| {
            format!("USAGE: {myself} class_hash tree_root [nonce [contract_version]]")
        })?
        .expect("there is always iterated over value");

    println!("{description}");

    println!("{res:x}");

    Ok(())
}
