use core::time::Duration;
use std::fs::canonicalize;
use std::sync::mpsc::channel;
use std::thread::sleep;
use std::thread::spawn;

use log::debug;
use log::error;
use log::info;
use log::warn;
use notify::event::CreateKind;
use notify::Config;
use notify::EventKind;
use notify::RecommendedWatcher;
use notify::RecursiveMode;
use notify::Watcher;
use tftp::types::FilePath;

use crate::blocking_reader::create_delayed_reader;
use crate::cli::BinError;
use crate::cli::BinResult;
use crate::cli::ClientCliConfig;
use crate::sender::start_send;

pub fn start_sync(
    config: ClientCliConfig,
    block_for_ms: u64,
    ignore_rate_control: bool,
    dir_path: Option<FilePath>,
) -> BinResult<()> {
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    let dir: String = dir_path.unwrap_or_else(|| ".".to_string());
    let full_dir_path = canonicalize(&dir).map_err(|e| BinError::from(e.to_string()))?;

    watcher
        .watch(&full_dir_path, RecursiveMode::Recursive)
        .map_err(|e| BinError::from(e.to_string()))?;

    info!("Watching directory {dir}");

    for res in rx {
        match res {
            // currently we listen for created file events and expect the file to be written faster than it is read + sent + confirmed
            // using a blocking reader in case there is a delay
            Ok(event) if matches!(event.kind, EventKind::Create(CreateKind::File)) => {
                let Some(local_path) = event.paths.first() else {
                    warn!("Unable to retrieve path for a created file. Ignoring");
                    continue;
                };

                let remote_path_without_prefix = local_path.strip_prefix(&full_dir_path);

                let local_path_str = local_path.to_string_lossy().to_string();

                let Ok(remote_path) = remote_path_without_prefix else {
                    warn!("Unable to to strip path from a created file {local_path_str}. Ignoring");
                    continue;
                };

                let remote_path_str = remote_path.to_string_lossy().to_string();

                debug!("File {local_path_str} created. Starting send as {remote_path_str}");

                let sender_config = config.clone();
                let block_thread = Duration::from_millis(block_for_ms);

                spawn(move || {
                    // give some time for writing
                    sleep(block_thread);
                    if let Err(e) = start_send(
                        local_path_str,
                        remote_path_str.into(),
                        sender_config,
                        |f| create_delayed_reader(f, block_thread),
                        ignore_rate_control,
                        false,
                    ) {
                        error!("Failed to synchronize file: {e}");
                    }
                });
            }
            _ => continue,
        }
    }
    Ok(())
}
