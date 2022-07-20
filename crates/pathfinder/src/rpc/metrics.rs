use std::time::Instant;

use jsonrpsee::core::middleware::Middleware;
use opentelemetry::{
    global,
    metrics::{Counter, ValueRecorder},
    KeyValue,
};

#[derive(Clone)]
/// Track rpc-related metrics
pub struct RpcMetricsMiddleware {
    call_count: Counter<u64>,
    call_error_count: Counter<u64>,
    call_duration: ValueRecorder<u64>,
}

impl RpcMetricsMiddleware {
    pub fn new() -> RpcMetricsMiddleware {
        let meter = global::meter("rpc");
        let call_count = meter
            .u64_counter("rpc.call_count")
            .with_description("Number of times the RPC method is called")
            .init();
        let call_error_count = meter
            .u64_counter("rpc.call_error_count")
            .with_description("Number of times the RPC method returns an error")
            .init();
        let call_duration = meter
            .u64_value_recorder("rpc.call_duration")
            .with_description("Duration (in ms) required to server the RPC call")
            .init();

        RpcMetricsMiddleware {
            call_count,
            call_error_count,
            call_duration,
        }
    }
}

impl Default for RpcMetricsMiddleware {
    fn default() -> Self {
        RpcMetricsMiddleware::new()
    }
}

impl Middleware for RpcMetricsMiddleware {
    type Instant = Instant;

    fn on_request(&self) -> Self::Instant {
        Instant::now()
    }

    fn on_result(&self, name: &str, success: bool, started_at: Self::Instant) {
        let mut attributes = vec![KeyValue::new("method", name.to_string())];
        self.call_count.add(1, &attributes);
        if !success {
            self.call_error_count.add(1, &attributes);
            attributes.push(KeyValue::new("status", "ERROR"));
        } else {
            attributes.push(KeyValue::new("status", "SUCCESS"));
        }
        let millis = started_at.elapsed().as_millis();
        self.call_duration.record(millis as u64, &attributes);
    }
}
