#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod api;
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

fn main() {}
