use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().count() != 1 {
        println!("compute_class_hash -- reads from stdin, outputs a class hash");
        println!(
            "the input read from stdin is expected to be a class definition, which is a json blob."
        );
        std::process::exit(1);
    }
    let mut s = Vec::new();
    std::io::stdin().read_to_end(&mut s).unwrap();
    let s = s;
    let class_hash = match starknet_gateway_types::class_hash::compute_class_hash(&s)? {
        starknet_gateway_types::class_hash::ComputedClassHash::Cairo(h) => h.0,
        starknet_gateway_types::class_hash::ComputedClassHash::Sierra(h) => h.0,
    };
    println!("{:x}", class_hash);
    Ok(())
}
