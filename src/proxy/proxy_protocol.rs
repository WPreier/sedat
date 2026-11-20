//! PROXY protocol v1/v2 encoders (outbound) and inbound trust/parse (allowlist).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::config::ip_in_allowlist;

/// PROXY v2 signature.
pub const PROXY_V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// Whether an inbound PROXY frame from `peer` may be trusted.
///
/// Default policy: inbound PROXY is off; when enabled, peer must match allowlist CIDRs.
#[must_use]
pub fn inbound_proxy_trusted(peer: IpAddr, enabled: bool, allowlist: &[String]) -> bool {
    if !enabled {
        return false;
    }
    ip_in_allowlist(peer, allowlist)
}

/// Outbound PROXY version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyVersion {
    /// Disabled.
    Off,
    /// Human-readable v1.
    V1,
    /// Binary v2.
    V2,
}

impl ProxyVersion {
    /// Parse config string.
    pub fn parse(s: &str) -> Self {
        match s {
            "v1" => Self::V1,
            "v2" => Self::V2,
            _ => Self::Off,
        }
    }
}

/// Encode PROXY v1 header line (including trailing CRLF).
pub fn encode_proxy_v1(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    let family = match client.ip() {
        IpAddr::V4(_) => "TCP4",
        IpAddr::V6(_) => "TCP6",
    };
    format!(
        "PROXY {family} {} {} {} {}\r\n",
        client.ip(),
        server.ip(),
        client.port(),
        server.port()
    )
    .into_bytes()
}

/// Encode PROXY protocol v2 binary header (LOCAL/PROXY command for stream).
pub fn encode_proxy_v2(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    // Signature
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(PROXY_V2_SIG);
    // ver_cmd: version=2, command=PROXY (0x1)
    buf.push(0x21);
    match (client.ip(), server.ip()) {
        (IpAddr::V4(c), IpAddr::V4(s)) => {
            // family=AF_INET (0x1), protocol=STREAM (0x1) => 0x11
            buf.push(0x11);
            buf.extend_from_slice(&12u16.to_be_bytes()); // addr length
            buf.extend_from_slice(&c.octets());
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&client.port().to_be_bytes());
            buf.extend_from_slice(&server.port().to_be_bytes());
        }
        (IpAddr::V6(c), IpAddr::V6(s)) => {
            buf.push(0x21); // AF_INET6 | STREAM
            buf.extend_from_slice(&36u16.to_be_bytes());
            buf.extend_from_slice(&c.octets());
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&client.port().to_be_bytes());
            buf.extend_from_slice(&server.port().to_be_bytes());
        }
        _ => {
            // Mixed families: emit LOCAL (no addr)
            buf.clear();
            buf.extend_from_slice(PROXY_V2_SIG);
            buf.push(0x20); // ver 2, LOCAL
            buf.push(0x00);
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    buf
}

/// Result of probing the start of a TCP stream for an inbound PROXY header.
#[derive(Debug)]
pub enum InboundProbe {
    /// No PROXY framing; `leftover` must be replayed to the HTTP/TLS stack.
    Absent {
        /// Bytes already read that are not a PROXY header.
        leftover: Vec<u8>,
    },
    /// Trusted peer sent a valid PROXY header; use `client` for rate-limit / logging.
    Accepted {
        /// Address claimed by the PROXY header.
        client: SocketAddr,
        /// Bytes after the PROXY header (start of HTTP/TLS).
        leftover: Vec<u8>,
    },
    /// PROXY framing from an untrusted peer (injection) or malformed header.
    Rejected,
}

fn looks_like_proxy_v1(buf: &[u8]) -> bool {
    buf.starts_with(b"PROXY ")
}

fn looks_like_proxy_v2(buf: &[u8]) -> bool {
    buf.len() >= 12 && &buf[..12] == PROXY_V2_SIG.as_slice()
}

/// Parse PROXY v1 from a buffer that starts with `PROXY `; returns (client, bytes_consumed).
fn parse_proxy_v1(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let end = buf.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&buf[..end]).ok()?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    // PROXY TCP4 cIP sIP cPort sPort
    if parts.len() < 6 || parts[0] != "PROXY" {
        return None;
    }
    if parts[1] == "UNKNOWN" {
        return None;
    }
    let cip: IpAddr = parts[2].parse().ok()?;
    let cport: u16 = parts[4].parse().ok()?;
    Some((SocketAddr::new(cip, cport), end + 2))
}

/// Parse PROXY v2 from a buffer that starts with the v2 signature.
fn parse_proxy_v2(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    if buf.len() < 16 {
        return None;
    }
    let ver_cmd = buf[12];
    let fam = buf[13];
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if buf.len() < 16 + len {
        return None;
    }
    let cmd = ver_cmd & 0x0f;
    if cmd == 0 {
        // LOCAL — keep peer; consume header
        return None; // signal caller to treat as absent-after-consume via special path
    }
    let addr = &buf[16..16 + len];
    let client = match fam {
        0x11 if len >= 12 => {
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            let port = u16::from_be_bytes([addr[8], addr[9]]);
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x21 if len >= 36 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr[0..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([addr[32], addr[33]]);
            SocketAddr::new(IpAddr::V6(ip), port)
        }
        _ => return None,
    };
    Some((client, 16 + len))
}

/// Whether inbound PROXY should be parsed on the plaintext TCP byte stream (before TLS).
#[must_use]
pub fn inbound_on_plaintext(enabled: bool, placement: &str) -> bool {
    enabled && placement != "after_tls"
}

/// Whether inbound PROXY should be parsed on the decrypted TLS byte stream (after handshake).
#[must_use]
pub fn inbound_on_tls(enabled: bool, placement: &str) -> bool {
    enabled && placement == "after_tls"
}

/// Probe any async reader for an inbound PROXY header under the allowlist policy.
///
/// Fail-closed: any PROXY framing is rejected unless `enabled` and the TCP peer
/// is in `allowlist`. When inbound is disabled (default), PROXY injection attempts are dropped.
pub async fn probe_inbound_proxy_reader<R: AsyncRead + Unpin>(
    stream: &mut R,
    peer: SocketAddr,
    enabled: bool,
    allowlist: &[String],
) -> io::Result<InboundProbe> {
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf[..16]).await?;
    if n == 0 {
        return Ok(InboundProbe::Absent {
            leftover: Vec::new(),
        });
    }
    buf.truncate(n);

    if looks_like_proxy_v1(&buf) {
        if !inbound_proxy_trusted(peer.ip(), enabled, allowlist) {
            return Ok(InboundProbe::Rejected);
        }
        while !buf.windows(2).any(|w| w == b"\r\n") {
            let mut b = [0u8; 1];
            let k = stream.read(&mut b).await?;
            if k == 0 {
                return Ok(InboundProbe::Rejected);
            }
            buf.push(b[0]);
            if buf.len() > 108 {
                return Ok(InboundProbe::Rejected);
            }
        }
        return match parse_proxy_v1(&buf) {
            Some((client, consumed)) => Ok(InboundProbe::Accepted {
                client,
                leftover: buf[consumed..].to_vec(),
            }),
            None => Ok(InboundProbe::Rejected),
        };
    }

    if looks_like_proxy_v2(&buf) || (n >= 12 && &buf[..12.min(n)] == &PROXY_V2_SIG[..12.min(n)]) {
        while buf.len() < 16 {
            let mut b = [0u8; 1];
            let k = stream.read(&mut b).await?;
            if k == 0 {
                if buf.starts_with(&PROXY_V2_SIG[..buf.len()]) && buf.len() >= 4 {
                    if !inbound_proxy_trusted(peer.ip(), enabled, allowlist) {
                        return Ok(InboundProbe::Rejected);
                    }
                    return Ok(InboundProbe::Rejected);
                }
                return Ok(InboundProbe::Absent { leftover: buf });
            }
            buf.push(b[0]);
        }
        if &buf[..12] != PROXY_V2_SIG.as_slice() {
            return Ok(InboundProbe::Absent { leftover: buf });
        }
        if !inbound_proxy_trusted(peer.ip(), enabled, allowlist) {
            return Ok(InboundProbe::Rejected);
        }
        let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        while buf.len() < 16 + len {
            let mut b = [0u8; 1];
            let k = stream.read(&mut b).await?;
            if k == 0 {
                return Ok(InboundProbe::Rejected);
            }
            buf.push(b[0]);
            if buf.len() > 16 + 216 {
                return Ok(InboundProbe::Rejected);
            }
        }
        let ver_cmd = buf[12];
        let cmd = ver_cmd & 0x0f;
        if cmd == 0 {
            return Ok(InboundProbe::Absent {
                leftover: buf[16 + len..].to_vec(),
            });
        }
        return match parse_proxy_v2(&buf) {
            Some((client, consumed)) => Ok(InboundProbe::Accepted {
                client,
                leftover: buf[consumed..].to_vec(),
            }),
            None => Ok(InboundProbe::Rejected),
        };
    }

    Ok(InboundProbe::Absent { leftover: buf })
}

/// Probe `stream` for an inbound PROXY header under the allowlist policy.
pub async fn probe_inbound_proxy(
    stream: &mut TcpStream,
    peer: SocketAddr,
    enabled: bool,
    allowlist: &[String],
) -> io::Result<InboundProbe> {
    probe_inbound_proxy_reader(stream, peer, enabled, allowlist).await
}

/// Stream with a byte prefix replayed before the underlying I/O.
pub struct PrefixedIo<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedIo<S> {
    /// Wrap `inner`, replaying `prefix` first (may be empty).
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }

    /// Consume this wrapper, returning the inner stream and any unread prefix bytes.
    pub fn into_parts(self) -> (S, Vec<u8>) {
        let pos = self.prefix.position() as usize;
        let rest = self.prefix.into_inner()[pos..].to_vec();
        (self.inner, rest)
    }

    /// Access inner stream.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Mutable access to inner stream.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

/// TCP stream with optional replay prefix (alias used on plaintext accept path).
pub type PrefixedStream = PrefixedIo<TcpStream>;

impl PrefixedIo<TcpStream> {
    /// Underlying peer address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pos = self.prefix.position() as usize;
        let prefix_len = self.prefix.get_ref().len();
        if pos < prefix_len {
            let rest = &self.prefix.get_ref()[pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Accept a connection, apply inbound PROXY policy, return stream + effective client address.
pub async fn accept_with_inbound_proxy(
    mut stream: TcpStream,
    peer: SocketAddr,
    enabled: bool,
    allowlist: &[String],
) -> io::Result<Option<(PrefixedStream, SocketAddr)>> {
    match probe_inbound_proxy(&mut stream, peer, enabled, allowlist).await? {
        InboundProbe::Absent { leftover } => {
            Ok(Some((PrefixedStream::new(stream, leftover), peer)))
        }
        InboundProbe::Accepted { client, leftover } => {
            Ok(Some((PrefixedStream::new(stream, leftover), client)))
        }
        InboundProbe::Rejected => Ok(None),
    }
}

/// Like [`accept_with_inbound_proxy`], but respects `inbound_placement`.
///
/// When `placement == "after_tls"`, plaintext PROXY is **not** trusted: framing is rejected
/// (fail-closed) so PP2-over-TLS is the only accepted inbound PROXY path.
pub async fn accept_with_inbound_proxy_placement(
    stream: TcpStream,
    peer: SocketAddr,
    enabled: bool,
    allowlist: &[String],
    placement: &str,
) -> io::Result<Option<(PrefixedStream, SocketAddr)>> {
    if inbound_on_plaintext(enabled, placement) {
        return accept_with_inbound_proxy(stream, peer, enabled, allowlist).await;
    }
    // after_tls or inbound disabled: still reject plaintext PROXY injection attempts.
    // When disabled, probe with enabled=false → Rejected on PROXY framing.
    // When after_tls, probe with enabled=false so plaintext PROXY cannot spoof.
    accept_with_inbound_proxy(stream, peer, false, allowlist).await
}

/// Apply inbound PROXY probe to an already-decrypted stream (PP2 over TLS).
pub async fn apply_inbound_after_tls<R: AsyncRead + Unpin>(
    stream: &mut R,
    peer: SocketAddr,
    enabled: bool,
    allowlist: &[String],
    placement: &str,
) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
    if !inbound_on_tls(enabled, placement) {
        return Ok(Some((peer, Vec::new())));
    }
    match probe_inbound_proxy_reader(stream, peer, enabled, allowlist).await? {
        InboundProbe::Absent { leftover } => Ok(Some((peer, leftover))),
        InboundProbe::Accepted { client, leftover } => Ok(Some((client, leftover))),
        InboundProbe::Rejected => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_roundtrip_shape() {
        let c: SocketAddr = "1.2.3.4:12345".parse().unwrap();
        let s: SocketAddr = "5.6.7.8:443".parse().unwrap();
        let b = encode_proxy_v1(c, s);
        let s = String::from_utf8(b).unwrap();
        assert!(s.starts_with("PROXY TCP4 1.2.3.4 5.6.7.8 12345 443\r\n"));
    }

    #[test]
    fn inbound_trust_default_deny() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!inbound_proxy_trusted(ip, false, &["10.0.0.0/8".into()]));
        assert!(inbound_proxy_trusted(ip, true, &["10.0.0.0/8".into()]));
        assert!(!inbound_proxy_trusted(ip, true, &["192.168.0.0/16".into()]));
    }

    #[test]
    fn placement_helpers() {
        assert!(inbound_on_plaintext(true, "before_tls"));
        assert!(!inbound_on_plaintext(true, "after_tls"));
        assert!(!inbound_on_plaintext(false, "before_tls"));
        assert!(inbound_on_tls(true, "after_tls"));
        assert!(!inbound_on_tls(true, "before_tls"));
        assert!(!inbound_on_tls(false, "after_tls"));
    }

    #[test]
    fn v2_signature_and_ports() {
        let c: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let s: SocketAddr = "10.0.0.2:9080".parse().unwrap();
        let b = encode_proxy_v2(c, s);
        assert_eq!(&b[..12], PROXY_V2_SIG.as_slice());
        assert_eq!(b[12], 0x21);
        assert_eq!(b[13], 0x11);
        assert_eq!(u16::from_be_bytes([b[14], b[15]]), 12);
        assert_eq!(&b[16..20], &[10, 0, 0, 1]);
        assert_eq!(&b[20..24], &[10, 0, 0, 2]);
        assert_eq!(u16::from_be_bytes([b[24], b[25]]), 40000);
        assert_eq!(u16::from_be_bytes([b[26], b[27]]), 9080);
    }

    #[test]
    fn parse_v1_client() {
        let raw = b"PROXY TCP4 203.0.113.9 10.0.0.1 4444 443\r\nGET / HTTP/1.1\r\n";
        let (client, n) = parse_proxy_v1(raw).unwrap();
        assert_eq!(client, "203.0.113.9:4444".parse().unwrap());
        assert!(raw[n..].starts_with(b"GET /"));
    }

    #[test]
    fn parse_v2_client() {
        let c: SocketAddr = "203.0.113.9:4444".parse().unwrap();
        let s: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let mut raw = encode_proxy_v2(c, s);
        raw.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let (client, n) = parse_proxy_v2(&raw).unwrap();
        assert_eq!(client, c);
        assert!(raw[n..].starts_with(b"GET /"));
    }
}
