use super::l2::Timings;
use opentelemetry::{
    global,
    metrics::{Counter, Meter, ValueRecorder},
};
use std::time::Duration;

/// Track sync-related metrics.
pub struct SyncMetrics {
    pub l1: L1Metrics,
    pub l2: L2Metrics,
}

pub struct L1Metrics {
    updates_count: Counter<u64>,
    reorgs_count: Counter<u64>,
    query_updates_count: Counter<u64>,
    restarts_count: Counter<u64>,
}

pub struct L2Metrics {
    updates_count: Counter<u64>,
    reorgs_count: Counter<u64>,
    new_contracts_count: Counter<u64>,
    restarts_count: Counter<u64>,
    hash_queries_count: Counter<u64>,
    contract_existance_queries_count: Counter<u64>,
    block_time_duration: ValueRecorder<f64>,
    block_download_time_duration: ValueRecorder<f64>,
    state_diff_time_duration: ValueRecorder<f64>,
    contract_deployment_time_duration: ValueRecorder<f64>,
    storage_updates_count: Counter<u64>,
}

impl SyncMetrics {
    pub fn new() -> SyncMetrics {
        let meter = global::meter("sync");
        let l1 = L1Metrics::new(&meter);
        let l2 = L2Metrics::new(&meter);
        SyncMetrics { l1, l2 }
    }
}

impl L1Metrics {
    pub fn new(meter: &Meter) -> L1Metrics {
        let updates_count = meter
            .u64_counter("l1.updates_count")
            .with_description("Number of l1 reorgs")
            .init();
        let reorgs_count = meter
            .u64_counter("l1.reorgs_count")
            .with_description("Number of L1 reorgs")
            .init();
        let query_updates_count = meter
            .u64_counter("l1.query_updates_count")
            .with_description("Number of L1 query updates")
            .init();
        let restarts_count = meter
            .u64_counter("l1.restarts_count")
            .with_description("Number of L1 restarts")
            .init();
        L1Metrics {
            updates_count,
            reorgs_count,
            query_updates_count,
            restarts_count,
        }
    }

    pub fn add_updates(&self, count: u64) {
        self.updates_count.add(count, &[]);
    }

    pub fn inc_reorgs(&self) {
        self.reorgs_count.add(1, &[]);
    }

    pub fn inc_query_updates(&self) {
        self.query_updates_count.add(1, &[]);
    }

    pub fn inc_restarts(&self) {
        self.restarts_count.add(1, &[]);
    }
}

impl L2Metrics {
    pub fn new(meter: &Meter) -> L2Metrics {
        let updates_count = meter
            .u64_counter("l2.updates_count")
            .with_description("Number of StarkNet updates")
            .init();
        let reorgs_count = meter
            .u64_counter("l2.reorgs_count")
            .with_description("Number of StarkNet reorgs")
            .init();
        let new_contracts_count = meter
            .u64_counter("l2.new_contracts_count")
            .with_description("Number of new StarkNet contracts")
            .init();
        let hash_queries_count = meter
            .u64_counter("l2.hash_queries_count")
            .with_description("Number of StarkNet hash queries")
            .init();
        let contract_existance_queries_count = meter
            .u64_counter("l2.contract_existance_queries_count")
            .with_description("Number of StarkNet contract existance queries")
            .init();
        let restarts_count = meter
            .u64_counter("l2.restarts_count")
            .with_description("Number of StarkNet restarts")
            .init();
        let block_time_duration = meter
            .f64_value_recorder("l2.block_time_duration")
            .with_description("Time (in ms) between two StarkNet blocks")
            .init();
        let block_download_time_duration = meter
            .f64_value_recorder("l2.block_download_time_duration")
            .with_description("Time (in ms) spent downloading StarkNet blocks")
            .init();
        let contract_deployment_time_duration = meter
            .f64_value_recorder("l2.contract_deployment_time_duration")
            .with_description("Time (in ms) spent deploying StarkNet contracts")
            .init();
        let state_diff_time_duration = meter
            .f64_value_recorder("l2.state_diff_time_duration")
            .with_description("Time (in ms) spent computing StarkNet state diff")
            .init();
        let storage_updates_count = meter
            .u64_counter("l2.storage_updates_duration")
            .with_description("Number (in ms) of StarkNet storage updates")
            .init();
        L2Metrics {
            updates_count,
            reorgs_count,
            new_contracts_count,
            hash_queries_count,
            contract_existance_queries_count,
            restarts_count,
            block_time_duration,
            block_download_time_duration,
            state_diff_time_duration,
            contract_deployment_time_duration,
            storage_updates_count,
        }
    }

    pub fn inc_updates(&self) {
        self.updates_count.add(1, &[]);
    }

    pub fn inc_reorgs(&self) {
        self.reorgs_count.add(1, &[]);
    }

    pub fn inc_new_contracts(&self) {
        self.new_contracts_count.add(1, &[]);
    }

    pub fn inc_hash_queries(&self) {
        self.hash_queries_count.add(1, &[]);
    }

    pub fn inc_contract_existance_queries(&self) {
        self.contract_existance_queries_count.add(1, &[]);
    }

    pub fn inc_restarts(&self) {
        self.restarts_count.add(1, &[]);
    }

    pub fn record_block_time(&self, time: &Duration) {
        self.block_time_duration.record(time.as_secs_f64(), &[]);
    }

    pub fn record_timings(&self, timings: &Timings) {
        self.block_download_time_duration
            .record(timings.block_download.as_secs_f64(), &[]);
        self.state_diff_time_duration
            .record(timings.state_diff_download.as_secs_f64(), &[]);
        self.contract_deployment_time_duration
            .record(timings.contract_deployment.as_secs_f64(), &[]);
    }

    pub fn record_storage_updates(&self, count: usize) {
        self.storage_updates_count.add(count as u64, &[]);
    }
}
