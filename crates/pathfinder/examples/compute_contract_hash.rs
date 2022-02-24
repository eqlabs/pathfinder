use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().count() != 1 {
        println!("compute_contract_hash -- reads from stdin, outputs a contract hash");
        println!("the input read from stdin is expected to be a contract definition, which is a json blob.");
        std::process::exit(1);
    }
    let mut s = Vec::new();
    std::io::stdin().read_to_end(&mut s).unwrap();
    let s = s;
    println!("{:x}", pathfinder_lib::state::compute_contract_hash(&s)?.0);
    Ok(())
}
