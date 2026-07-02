use std::net::{IpAddr, SocketAddr};

use http::Request;
use tonic::transport::server::TcpConnectInfo;

pub(crate) fn peer_ip_from_request<B>(request: &Request<B>) -> Option<IpAddr> {
    request
        .extensions()
        .get::<TcpConnectInfo>()
        .and_then(TcpConnectInfo::remote_addr)
        .map(|addr| normalize_ip(addr.ip()))
}

pub(crate) fn peer_key_from_request<B>(request: &Request<B>) -> String {
    peer_ip_from_request(request)
        .map(|addr| addr.to_string())
        .unwrap_or_default()
}

fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

#[allow(dead_code)]
pub(crate) fn normalize_socket_addr(addr: SocketAddr) -> IpAddr {
    normalize_ip(addr.ip())
}
