#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod api;
mod config;
mod db;
mod notify;
mod text;

fn main() {}
