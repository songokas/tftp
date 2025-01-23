use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use core::time::Duration;
use std::collections::HashMap;
use std::fs::canonicalize;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::sleep;
use std::thread::spawn;

use log::debug;
use log::error;
use log::info;
use log::warn;
use notify::event::AccessKind;
use notify::event::AccessMode;
use notify::event::CreateKind;
use notify::Config;
use notify::EventKind;
use notify::RecommendedWatcher;
use notify::RecursiveMode;
use notify::Watcher;
use tftp_dus::types::FilePath;

use crate::blocking_reader::create_delayed_reader;
use crate::cli::ClientCliConfig;
use crate::error::BinError;
use crate::error::BinResult;
use crate::io::create_reader;
use crate::sender::start_send;

pub fn start_sync(
    config: ClientCliConfig,
    dir_path: Option<FilePath>,
    start_on_create: bool,
    block_for_ms: u64,
) -> BinResult<()> {
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    let dir: String = dir_path.unwrap_or_else(|| ".".to_string());
    let sync_dir = canonicalize(&dir).map_err(|e| BinError::from(e.to_string()))?;

    watcher
        .watch(&sync_dir, RecursiveMode::Recursive)
        .map_err(|e| BinError::from(e.to_string()))?;

    info!("Watching directory {dir}");

    let mut paths_pending = HashMap::new();

    for res in rx {
        match (res, start_on_create) {
            // starting read on not a fully written file
            (Ok(event), true) if matches!(event.kind, EventKind::Create(CreateKind::File)) => {
                let Some((local_path, remote_path)) = get_paths(&event.paths, &sync_dir) else {
                    continue;
                };

                debug!("File {local_path} created. Starting to send as {remote_path}");

                let sender_config = config.clone();
                let block_thread = Duration::from_millis(block_for_ms);

                let finished: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
                paths_pending.insert(local_path.clone(), finished.clone());

                spawn(move || {
                    // give some time for writing
                    sleep(block_thread);
                    if let Err(e) = start_send(
                        local_path.clone(),
                        remote_path.into(),
                        sender_config,
                        |f| create_delayed_reader(f, finished.clone()),
                        false,
                    ) {
                        error!("Failed to synchronize file {local_path}: {e}");
                    }
                });
            }
            // let the reader know that file has been written
            (Ok(event), true)
                if matches!(
                    event.kind,
                    EventKind::Access(AccessKind::Close(AccessMode::Write))
                ) =>
            {
                let Some((local_path, _)) = get_paths(&event.paths, &sync_dir) else {
                    continue;
                };

                debug!("File {local_path} was closed");

                if let Some(f) = paths_pending.remove(&local_path) {
                    f.store(true, Ordering::Relaxed);
                } else {
                    warn!("Unknown file {local_path} ignoring");
                }
            }
            // start once the file is written
            (Ok(event), false)
                if matches!(
                    event.kind,
                    EventKind::Access(AccessKind::Close(AccessMode::Write))
                ) =>
            {
                let Some((local_path, remote_path)) = get_paths(&event.paths, &sync_dir) else {
                    continue;
                };

                debug!("File {local_path} finished writing. Starting to send as {remote_path}");

                let sender_config = config.clone();

                spawn(move || {
                    if let Err(e) = start_send(
                        local_path.clone(),
                        remote_path.into(),
                        sender_config,
                        create_reader,
                        false,
                    ) {
                        error!("Failed to synchronize file {local_path}: {e}");
                    }
                });
            }
            (Ok(event), _) => debug!("Event received {event:?}"),
            _ => continue,
        }
    }
    Ok(())
}

fn get_paths(local_paths: &[PathBuf], sync_dir: &PathBuf) -> Option<(String, String)> {
    let Some(local_path) = local_paths.first() else {
        warn!("Unable to retrieve path for a created file. Ignoring");
        return None;
    };
    let remote_path_without_prefix = local_path.strip_prefix(sync_dir);

    let local_path_str = local_path.to_string_lossy().to_string();

    let Ok(remote_path) = remote_path_without_prefix else {
        warn!("Unable to to strip path from a created file {local_path_str}. Ignoring");
        return None;
    };

    let remote_path_str = remote_path.to_string_lossy().to_string();

    Some((local_path_str, remote_path_str))
}
