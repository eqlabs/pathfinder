use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::{
    DefaultOnEos,
    DefaultOnFailure,
    DefaultOnRequest,
    DefaultOnResponse,
    TraceLayer,
};
use tracing::Level;

pub(crate) fn trace_layer(
) -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>, RequestHeaderSpan> {
    tower_http::trace::TraceLayer::new_for_http()
        // Records request ID header value in the span.
        .make_span_with(RequestHeaderSpan)
        .on_failure(DefaultOnFailure::default().level(Level::DEBUG))
        .on_request(DefaultOnRequest::default().level(Level::TRACE))
        .on_response(DefaultOnResponse::default().level(Level::TRACE))
        .on_eos(DefaultOnEos::default().level(Level::TRACE))
}

#[derive(Copy, Clone)]
pub(crate) struct RequestHeaderSpan;

impl<B> tower_http::trace::MakeSpan<B> for RequestHeaderSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        let x_request_id = request
            .headers()
            .get("x-request-id")
            .and_then(|x| x.to_str().ok());

        if let Some(x_request_id) = x_request_id {
            tracing::debug_span!(
                "request",
                uri = %request.uri(),
                version = ?request.version(),
                ?x_request_id,
            )
        } else {
            tracing::debug_span!(
                "request",
                uri = %request.uri(),
                version = ?request.version(),
            )
        }
    }
}
