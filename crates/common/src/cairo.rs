#[cfg(test)]
mod tests {
    use cairo_lang_starknet::{
        casm_contract_class::CasmContractClass, contract_class::ContractClass,
    };

    #[test]
    fn starknet_sierra_to_casm_compilation() {
        let contract_class: ContractClass =
            serde_json::from_slice(include_bytes!("../fixtures/test_contract.json")).unwrap();
        let casm_contract = CasmContractClass::from_contract_class(contract_class).unwrap();
        let casm_contract = serde_json::to_value(casm_contract).unwrap();
        pretty_assertions::assert_eq!(
            casm_contract,
            serde_json::from_slice::<serde_json::Value>(include_bytes!(
                "../fixtures/test_contract.casm"
            ))
            .unwrap()
        );
    }
}
