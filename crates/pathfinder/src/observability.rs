use futures::Future;
use opentelemetry_prometheus::{Encoder, PrometheusExporter, TextEncoder};
use std::net::SocketAddr;
use std::pin::Pin;
use warp::http::Response as HttpResponse;
use warp::hyper::StatusCode;
use warp::Filter;

type ServerFuture = Pin<Box<dyn Future<Output = ()>>>;

pub fn init_prometheus_exporter() -> PrometheusExporter {
    // Set default histogram boundaries to something more useful.
    // The opentelemetry_prometheus crate does not allow to set buckets
    // for each metric individually but in pathfinder's case all
    // value recorders are used to measure request latencies.
    //
    // The buckets where chosen based on real-world measured latencies.
    opentelemetry_prometheus::exporter()
        .with_default_histogram_boundaries(vec![10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 3000.0, 5000.0])
        .init()
}

/// Run metrics server if `addr` is specified.
pub fn run_server(
    addr: Option<SocketAddr>,
    exporter: PrometheusExporter,
) -> anyhow::Result<(ServerFuture, Option<SocketAddr>)> {
    if let Some(addr) = addr {
        let readyz = warp::path!("readyz").and(warp::get()).map({
            move || {
                HttpResponse::builder()
                    .status(StatusCode::OK)
                    .body("ok")
                    .unwrap()
            }
        });

        let livez = warp::path!("livez").and(warp::get()).map({
            move || {
                HttpResponse::builder()
                    .status(StatusCode::OK)
                    .body("ok")
                    .unwrap()
            }
        });
        let metrics = warp::path!("metrics").and(warp::get()).map({
            move || {
                let mut buffer = Vec::new();
                let encoder = TextEncoder::new();
                let metric_families = exporter.registry().gather();
                if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
                    return HttpResponse::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(err.to_string().into_bytes())
                        .unwrap();
                }
                HttpResponse::builder()
                    .status(StatusCode::OK)
                    .body(buffer)
                    .unwrap()
            }
        });

        let (bind_addr, server) = warp::serve(livez.or(readyz).or(metrics)).bind_ephemeral(addr);
        Ok((Box::pin(server), Some(bind_addr)))
    } else {
        let do_nothing = Box::pin(std::future::pending::<()>());
        Ok((do_nothing, None))
    }
}
