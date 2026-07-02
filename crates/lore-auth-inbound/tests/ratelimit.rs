use std::{convert::Infallible, net::SocketAddr};

use http::{Request, Response};
use lore_auth_inbound::ratelimit::RateLimitLayer;
use tonic::Code;
use tower::{Layer, Service, ServiceExt, service_fn};

#[tokio::test]
async fn start_auth_session_rate_limit_returns_resource_exhausted_per_peer() {
    let mut service = RateLimitLayer::new(60, std::time::Duration::from_secs(60)).layer(
        service_fn(|_req| async { Ok::<_, Infallible>(Response::new(tonic::body::empty_body())) }),
    );

    let mut rejected = None;
    for _ in 0..65 {
        let result = service
            .ready()
            .await
            .expect("service ready")
            .call(http_request(
                "/epic_urc.UrcAuthApi/StartAuthSession",
                "203.0.113.20:443",
            ))
            .await;
        let response = result.expect("rate-limit response is HTTP/gRPC encoded");
        if let Some(status) = tonic::Status::from_header_map(response.headers()) {
            rejected = Some(status);
            break;
        }
    }
    assert_eq!(
        rejected.expect("rate limit is reached").code(),
        Code::ResourceExhausted
    );

    service
        .ready()
        .await
        .expect("service ready")
        .call(http_request(
            "/epic_urc.UrcAuthApi/StartAuthSession",
            "203.0.113.21:443",
        ))
        .await
        .expect("other peer has its own bucket");
}

#[tokio::test]
async fn rate_limit_does_not_apply_to_other_auth_methods() {
    let mut service = RateLimitLayer::new(60, std::time::Duration::from_secs(60)).layer(
        service_fn(|_req| async { Ok::<_, Infallible>(Response::new(tonic::body::empty_body())) }),
    );

    for _ in 0..65 {
        service
            .ready()
            .await
            .expect("service ready")
            .call(http_request(
                "/epic_urc.UrcAuthApi/GetAuthSession",
                "203.0.113.22:443",
            ))
            .await
            .expect("non-start method is not rate limited");
    }
}

fn http_request(path: &str, remote_addr: &str) -> Request<()> {
    let mut request = Request::builder()
        .uri(path)
        .body(())
        .expect("request builds");
    request
        .extensions_mut()
        .insert(tonic::transport::server::TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(
                remote_addr
                    .parse::<SocketAddr>()
                    .expect("socket addr parses"),
            ),
        });
    request
}
