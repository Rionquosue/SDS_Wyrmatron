//! Wyrmatron: Telegram utility bot and notification relay (SDS-Wyrmatron).

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod api;
mod app;
mod config;
mod db;
mod extract;
mod fetch;
mod ffmpeg;
mod http;
mod media;
mod notify;
mod telegram;
mod text;

use std::io::{Read, Write};
use std::process::ExitCode;

use base64::Engine;

const USAGE: &str = "usage: wyrmatron [serve | healthcheck | gen-key | hash-key | version]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("serve") {
        "serve" => app::serve(),
        "healthcheck" => healthcheck(),
        "gen-key" => {
            // A new API key and the hash to put in the configuration.
            let key =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
            println!(
                "key:        {key}\nkey_sha256: {}",
                hex::encode(api::auth::sha256(key.as_bytes()))
            );
            ExitCode::SUCCESS
        }
        "hash-key" => {
            let mut key = String::new();
            if std::io::stdin().read_to_string(&mut key).is_err() || key.trim().is_empty() {
                eprintln!("pipe the key on standard input");
                return ExitCode::FAILURE;
            }
            println!("{}", hex::encode(api::auth::sha256(key.trim().as_bytes())));
            ExitCode::SUCCESS
        }
        "version" | "--version" => {
            println!("wyrmatron {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Docker HEALTHCHECK: a plain HTTP request to the readiness endpoint, with
/// no TLS or runtime setup.
fn healthcheck() -> ExitCode {
    let port = config::Config::load(None)
        .map(|c| c.server.listen.port())
        .unwrap_or(8080);
    let check = || -> std::io::Result<bool> {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut s = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        s.write_all(b"GET /health/ready HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf)?;
        Ok(buf[..n].starts_with(b"HTTP/1.1 200") || buf[..n].starts_with(b"HTTP/1.0 200"))
    };
    match check() {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
