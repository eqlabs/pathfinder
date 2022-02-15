use web3::ethabi::{Contract, Event, Function};

const CORE_IMPL_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/core_impl.json"
));

const GPS_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/gps_statement_verifier.json"
));

const MEMPAGE_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/memory_page_fact_registry.json"
));

lazy_static::lazy_static!(
    pub static ref STATE_UPDATE_EVENT: Event = core_contract().event("LogStateUpdate")
            .expect("LogStateUpdate event not found in core contract ABI").to_owned();
    pub static ref STATE_TRANSITION_FACT_EVENT: Event = core_contract().event("LogStateTransitionFact")
            .expect("LogStateTransitionFact event not found in core contract ABI").to_owned();
    pub static ref MEMORY_PAGE_HASHES_EVENT: Event = gps_contract().event("LogMemoryPagesHashes")
            .expect("LogMemoryPagesHashes event not found in GPS contract ABI").to_owned();
    pub static ref MEMORY_PAGE_FACT_CONTINUOUS_EVENT: Event = mempage_contract().event("LogMemoryPageFactContinuous")
            .expect("LogMemoryPageFactContinuous event not found in Memory Page Fact Registry contract ABI").to_owned();

    pub static ref REGISTER_MEMORY_PAGE_FUNCTION: Function = mempage_contract().function("registerContinuousMemoryPage")
            .expect("registerContinuousMemoryPage function not found in Memory Page Fact Registry contract ABI").to_owned();
);

fn core_contract() -> Contract {
    Contract::load(CORE_IMPL_ABI).expect("Core contract ABI is invalid")
}

fn gps_contract() -> Contract {
    Contract::load(GPS_ABI).expect("GPS contract ABI is invalid")
}

fn mempage_contract() -> Contract {
    Contract::load(MEMPAGE_ABI).expect("Mempage contract ABI is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    mod contract {
        use super::*;

        #[test]
        fn core() {
            let _contract = core_contract();
        }

        #[test]
        fn gps() {
            let _contract = gps_contract();
        }

        #[test]
        fn mempage() {
            let _contract = mempage_contract();
        }
    }

    mod event {
        use super::*;

        #[test]
        fn state_update() {
            let _event = STATE_UPDATE_EVENT.clone();
        }

        #[test]
        fn state_transition_fact() {
            let _event = STATE_TRANSITION_FACT_EVENT.clone();
        }

        #[test]
        fn memory_page_hashes() {
            let _event = MEMORY_PAGE_HASHES_EVENT.clone();
        }

        #[test]
        fn memory_page_fact() {
            let _event = MEMORY_PAGE_FACT_CONTINUOUS_EVENT.clone();
        }
    }
}
