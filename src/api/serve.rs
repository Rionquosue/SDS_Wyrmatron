//! HTTP/1.1 accept loop. `axum::serve` builds its connections without a
//! timer, so Hyper's header-read timeout never fires and a client can hold a
//! connection open indefinitely by trickling headers (slowloris). This loop
//! sets the timer and timeout, caps concurrent connections, and drains
//! connections on shutdown.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Time allowed to receive a complete request head.
    pub header_read_timeout: Duration,
    /// Simultaneous connections; further connections are closed at accept.
    pub max_connections: usize,
    /// Time in-flight requests get to finish after shutdown starts.
    pub drain: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            max_connections: 256,
            drain: Duration::from_secs(10),
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let mut shutdown = pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            a = listener.accept() => a,
        };
        let (stream, peer) = match accepted {
            Ok(a) => a,
            Err(e) => {
                // Usually out of file descriptors: back off instead of spinning.
                warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!(%peer, "connection limit reached; closing");
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let service = TowerToHyperService::new(app.clone());
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(limits.header_read_timeout)
            .max_buf_size(64 * 1024)
            .serve_connection(TokioIo::new(stream), service);
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(%peer, error = %e, "connection ended with an error");
            }
            drop(permit);
        });
    }
    drop(listener);
    if tokio::time::timeout(limits.drain, graceful.shutdown())
        .await
        .is_err()
    {
        warn!("connections did not drain within the grace period");
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use axum::routing::get;

    use super::*;

    async fn start(
        limits: Limits,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/", get(|| async { "ok" }));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(serve(listener, app, limits, async move {
            let _ = rx.await;
        }));
        (addr, tx, task)
    }

    fn closed_by_server(mut s: TcpStream) -> bool {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 256];
        // The server either closes (0 bytes) or answers 408, then closes.
        s.read(&mut buf).is_ok()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_and_times_out_slow_headers() {
        let limits = Limits {
            header_read_timeout: Duration::from_millis(300),
            max_connections: 4,
            drain: Duration::from_secs(1),
        };
        let (addr, stop, task) = start(limits).await;
        let ok = tokio::task::spawn_blocking(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out.starts_with("HTTP/1.1 200") && out.ends_with("ok")
        })
        .await
        .unwrap();
        assert!(ok);
        // A client that never finishes its headers is disconnected.
        let slow = tokio::task::spawn_blocking(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
                .unwrap();
            let started = std::time::Instant::now();
            closed_by_server(s) && started.elapsed() < Duration::from_secs(3)
        })
        .await
        .unwrap();
        assert!(slow, "slow headers must be cut off by the header timeout");
        stop.send(()).unwrap();
        task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn caps_concurrent_connections() {
        let limits = Limits {
            header_read_timeout: Duration::from_secs(30),
            max_connections: 2,
            drain: Duration::from_secs(1),
        };
        let (addr, stop, task) = start(limits).await;
        let held: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(addr).unwrap()).collect();
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A third connection is accepted by the kernel and closed at once.
        let over = tokio::task::spawn_blocking(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut buf = [0u8; 64];
            matches!(s.read(&mut buf), Ok(0) | Err(_))
        })
        .await
        .unwrap();
        assert!(over, "connections over the cap are closed");
        drop(held);
        stop.send(()).unwrap();
        task.await.unwrap();
    }
}
