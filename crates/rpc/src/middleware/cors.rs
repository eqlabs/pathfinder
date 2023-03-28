use http::HeaderValue;
use pathfinder_common::AllowedOrigins;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub fn with_allowed_origins(allowed_origins: AllowedOrigins) -> CorsLayer {
    let allowed_origins = match allowed_origins {
        AllowedOrigins::Any => AllowOrigin::any(),
        AllowedOrigins::List(x) => AllowOrigin::list(x.into_iter().map(|s| {
            HeaderValue::from_maybe_shared(s.into_bytes())
                .expect("passed type is 'shared' (i.e. owned byte buffer)")
        })),
    };

    CorsLayer::new()
        .allow_methods([hyper::Method::POST])
        .allow_origin(allowed_origins)
        .allow_headers([hyper::header::CONTENT_TYPE])
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn cors_works() {
        // unimplemented!();
    }
}
