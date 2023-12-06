use std::sync::atomic::AtomicU64;
use std::sync::Arc;

// A `MakeRequestId` that increments an atomic counter
#[derive(Clone, Default)]
pub(crate) struct RequestIdSource {
    counter: Arc<AtomicU64>,
}

impl tower_http::request_id::MakeRequestId for RequestIdSource {
    fn make_request_id<B>(
        &mut self,
        _: &http::Request<B>,
    ) -> Option<tower_http::request_id::RequestId> {
        let request_id = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .to_string()
            .parse()
            .unwrap();

        Some(tower_http::request_id::RequestId::new(request_id))
    }
}
