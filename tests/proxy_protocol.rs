//! Phase 5: PROXY protocol encoding tests.

use std::net::SocketAddr;

use sedat::proxy::{encode_proxy_v1, encode_proxy_v2};

#[test]
fn proxy_v2_haproxy_compatible_shape() {
    let c: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    let s: SocketAddr = "198.51.100.2:9080".parse().unwrap();
    let b = encode_proxy_v2(c, s);
    assert_eq!(&b[0..12], b"\r\n\r\n\0\r\nQUIT\n");
    assert_eq!(b[12], 0x21);
    assert_eq!(b[13], 0x11);
}

#[test]
fn proxy_v1_line() {
    let c: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    let s: SocketAddr = "198.51.100.2:9080".parse().unwrap();
    let line = String::from_utf8(encode_proxy_v1(c, s)).unwrap();
    assert_eq!(line, "PROXY TCP4 192.0.2.1 198.51.100.2 12345 9080\r\n");
}
