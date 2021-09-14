mod config;

fn main() {
    match config::Configuration::parse_cmd_line_and_cfg_file() {
        Ok(cfg) => println!("Configuration: {:?}", cfg),
        Err(err) => eprintln!("Configuration failed: {}", err),
    }
}
