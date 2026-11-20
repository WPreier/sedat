//! Phase 0 example: bind and answer with a placeholder 503.
use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

async fn handle(_req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(
            b"SeDat placeholder - not yet configured\n",
        )))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = "127.0.0.1:18080".parse()?;
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{addr} — placeholder 503");
    let (stream, _) = listener.accept().await?;
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(io, service_fn(handle))
        .await?;
    Ok(())
}
