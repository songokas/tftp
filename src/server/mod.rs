mod config;
mod connection;
mod connection_builder;
mod extensions;
mod helpers;
#[cfg(all(feature = "std", feature = "multi_thread"))]
mod multi_thread;
mod readers_available;
#[cfg(not(feature = "multi_thread"))]
mod single_thread;
mod validation;
mod wait_control;
pub use config::ServerConfig;
#[cfg(all(feature = "std", feature = "multi_thread"))]
pub use multi_thread::server;
#[cfg(not(feature = "multi_thread"))]
pub use single_thread::server;
