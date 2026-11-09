#[cfg(not(feature = "multi_thread"))]
mod client_store;
mod config;
pub(crate) mod connection;
mod connection_builder;
mod extensions;
pub(crate) mod helpers;
#[cfg(feature = "multi_thread")]
mod multi_thread;
mod readers_available;
#[cfg(feature = "encryption")]
mod session_encryption;
#[cfg(not(feature = "encryption"))]
use crate::features::no_server_session_encryption as session_encryption;
#[cfg(not(feature = "multi_thread"))]
mod single_thread;
#[cfg(feature = "multi_thread")]
mod spawner;
mod validation;
mod wait_control;
pub use config::ServerConfig;
#[cfg(feature = "multi_thread")]
pub use multi_thread::server;
#[cfg(feature = "multi_thread")]
pub use multi_thread::Job;
#[cfg(not(feature = "multi_thread"))]
pub use single_thread::server;
#[cfg(feature = "multi_thread")]
pub use spawner::Spawner;
#[cfg(feature = "multi_thread")]
pub use spawner::TaskHandle;
#[cfg(all(feature = "std", feature = "multi_thread"))]
pub use spawner::ThreadSpawner;
