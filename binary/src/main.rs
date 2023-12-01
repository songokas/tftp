#[cfg(feature = "sync")]
mod blocking_reader;
mod cli;
mod io;
mod macros;
mod receiver;
mod sender;
mod socket;
#[cfg(feature = "sync")]
mod sync;

use clap::Parser;
use env_logger::Builder;
use env_logger::Env;
use io::instant_callback;
use rand::rngs::OsRng;
use receiver::start_receive;
use sender::start_send;
#[cfg(feature = "sync")]
use sync::start_sync;
use tftp::server::server;

use crate::cli::Args;
use crate::cli::BinError;
use crate::cli::BinResult;
use crate::cli::Commands;
use crate::io::create_reader;
use crate::io::create_server_reader;
use crate::io::create_server_writer;
use crate::io::create_writer;
use crate::socket::*;

// tftp send localhost:3000 /tmp/a --remote-path long/a
// tftp receive localhost:3000 long/a --local-path /tmp/a
// tftp server localhost:300 /tmp --allow-overwrite
fn main() -> BinResult<()> {
    let args = Args::parse();
    Builder::from_env(Env::default().default_filter_or(args.verbosity.as_str()))
        .format_target(cfg!(debug_assertions))
        .init();

    match args.command {
        Commands::Send {
            local_path,
            remote_path,
            config,
            ignore_rate_control,
            #[cfg(feature = "seek")]
            prefer_seek,
        } => start_send(
            local_path,
            remote_path,
            config,
            create_reader,
            ignore_rate_control,
            #[cfg(feature = "seek")]
            prefer_seek,
            #[cfg(not(feature = "seek"))]
            false,
        )
        .map(|_| ()),
        #[cfg(feature = "sync")]
        Commands::Sync {
            dir_path,
            config,
            block_duration,
            ignore_rate_control,
        } => start_sync(config, block_duration, ignore_rate_control, dir_path).map(|_| ()),

        Commands::Receive {
            config,
            local_path,
            remote_path,
        } => start_receive(local_path, remote_path, config, create_writer).map(|_| ()),
        Commands::Server(config) => {
            let config = config.try_into()?;
            // init_logger(config.listen);
            server(
                config,
                create_server_reader,
                create_server_writer,
                create_socket,
                create_bound_socket,
                instant_callback,
                OsRng,
            )
            .map_err(|e| BinError::from(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread::sleep;
    use std::thread::spawn;
    use std::time::Duration;

    use tftp::config::MAX_DATA_BLOCK_SIZE;
    use tftp::encryption::*;
    use tftp::error::DefaultBoxedResult;
    use tftp::key_management::AuthorizedKeys;
    use tftp::server::server;
    use tftp::server::ServerConfig;
    use tftp::std_compat::io;
    use tftp::types::FilePath;
    #[allow(unused_imports)]
    use tftp::types::ShortString;

    use super::*;
    use crate::cli::ClientCliConfig;

    #[cfg(feature = "encryption")]
    #[test]
    fn test_client_full_encryption() {
        // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        for w in [1, 4] {
            let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let key: [u8; 32] = bytes.try_into().unwrap();
            let server_private_key: PrivateKey = key.into();
            client_send(
                EncryptionLevel::Protocol,
                w,
                Some(server_private_key.clone()),
                None,
                None,
            );
            client_receive(
                EncryptionLevel::Protocol,
                w,
                Some(server_private_key),
                None,
                None,
            );
        }
    }

    #[allow(unused_must_use)]
    #[cfg(feature = "encryption")]
    #[test]
    fn test_client_full_encryption_only_authorized() {
        // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        for w in [1, 4] {
            let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let key: [u8; 32] = bytes.try_into().unwrap();
            let server_private_key: PrivateKey = key.into();
            let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let key: [u8; 32] = bytes.try_into().unwrap();
            let client_private_key: PrivateKey = key.into();
            let mut authorized_keys = AuthorizedKeys::new();

            authorized_keys.push(PublicKey::from(&client_private_key));
            client_send(
                EncryptionLevel::Protocol,
                w,
                Some(server_private_key.clone()),
                #[cfg(feature = "encryption")]
                Some(authorized_keys.clone()),
                Some(client_private_key.clone()),
            );
            client_receive(
                EncryptionLevel::Protocol,
                w,
                Some(server_private_key),
                #[cfg(feature = "encryption")]
                Some(authorized_keys),
                Some(client_private_key),
            );
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_client_protocol_encryption() {
        for w in [1, 4] {
            client_send(EncryptionLevel::Protocol, w, None, None, None);
            client_receive(EncryptionLevel::Protocol, w, None, None, None);
        }
    }

    #[allow(unused_must_use)]
    #[cfg(feature = "encryption")]
    #[test]
    fn test_client_protocol_encryption_authorized() {
        // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        for w in [1, 4] {
            let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let key: [u8; 32] = bytes.try_into().unwrap();
            let client_private_key: PrivateKey = key.into();
            let mut authorized_keys = AuthorizedKeys::new();
            authorized_keys.push(PublicKey::from(&client_private_key));
            client_send(
                EncryptionLevel::Protocol,
                w,
                None,
                Some(authorized_keys.clone()),
                Some(client_private_key.clone()),
            );
            client_receive(
                EncryptionLevel::Protocol,
                w,
                None,
                Some(authorized_keys),
                Some(client_private_key),
            );
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_client_data_encryption() {
        // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        for w in [1, 4] {
            client_send(EncryptionLevel::Data, w, None, None, None);
            client_receive(EncryptionLevel::Data, w, None, None, None);
        }
    }

    #[test]
    fn test_client_no_encryption() {
        // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        //     .format_timestamp_micros()
        //     .init();
        for w in [1, 4] {
            client_send(EncryptionLevel::None, w, None, None, None);
            client_receive(EncryptionLevel::None, w, None, None, None);
        }
    }

    fn client_send(
        encryption_level: EncryptionLevel,
        window_size: u64,
        server_private_key: Option<PrivateKey>,
        authorized_keys: Option<AuthorizedKeys>,
        _client_private_key: Option<PrivateKey>,
    ) {
        let bytes: Vec<u8> = (0..2000).map(|_| rand::random::<u8>()).collect();
        let expected_size = bytes.len();
        let expected_data = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let server_port = get_port();
        #[cfg(feature = "encryption")]
        let server_public_key = server_private_key
            .as_ref()
            .map(|k| encode_public_key(&PublicKey::from(k)).unwrap());
        let _server = {
            let d = expected_data.clone();
            spawn(move || {
                start_server(
                    server_port,
                    Vec::new(),
                    d,
                    server_private_key,
                    authorized_keys,
                )
            })
        };
        #[cfg(feature = "encryption")]
        let client_private_key = _client_private_key
            .as_ref()
            .map(|k| encode_private_key(k).unwrap());
        let client = {
            let d = bytes.clone();
            spawn(move || {
                sleep(Duration::from_millis(100));
                start_send_file(
                    server_port,
                    encryption_level,
                    window_size,
                    d,
                    #[cfg(feature = "encryption")]
                    server_public_key,
                    #[cfg(feature = "encryption")]
                    client_private_key,
                )
            })
        };
        let result = client.join().unwrap();
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(result.unwrap(), expected_size);
        assert_eq!(&bytes, expected_data.lock().unwrap().get_ref());
    }

    fn client_receive(
        encryption_level: EncryptionLevel,
        window_size: u64,
        _server_private_key: Option<PrivateKey>,
        _authorized_keys: Option<AuthorizedKeys>,
        _client_private_key: Option<PrivateKey>,
    ) {
        let bytes: Vec<u8> = (0..2000).map(|_| rand::random::<u8>()).collect();
        let expected_size = bytes.len();
        let expected_data = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let server_port = get_port();
        #[cfg(feature = "encryption")]
        let server_public_key = _server_private_key
            .as_ref()
            .map(|k| encode_public_key(&PublicKey::from(k)).unwrap());
        let _server = {
            let d = bytes.clone();
            spawn(move || {
                start_server(
                    server_port,
                    d,
                    Default::default(),
                    _server_private_key,
                    _authorized_keys,
                )
            })
        };

        #[cfg(feature = "encryption")]
        let client_private_key = _client_private_key
            .as_ref()
            .map(|k| encode_private_key(k).unwrap());
        let client = {
            let d = expected_data.clone();
            spawn(move || {
                sleep(Duration::from_millis(100));
                start_receive_file(
                    server_port,
                    encryption_level,
                    window_size,
                    d,
                    #[cfg(feature = "encryption")]
                    server_public_key,
                    #[cfg(feature = "encryption")]
                    client_private_key,
                )
            })
        };
        let result = client.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap(), expected_size);
        assert_eq!(&bytes, expected_data.lock().unwrap().get_ref());
    }

    fn start_send_file(
        server_port: u16,
        _encryption_level: EncryptionLevel,
        window_size: u64,
        bytes: Vec<u8>,
        #[cfg(feature = "encryption")] server_public_key: Option<ShortString>,
        #[cfg(feature = "encryption")] private_key: Option<ShortString>,
    ) -> BinResult<usize> {
        let cli_config = ClientCliConfig {
            endpoint: format!("127.0.0.1:{server_port}").parse().unwrap(),
            listen: "127.0.0.1:0".parse().unwrap(),
            request_timeout: 1000,
            block_size: 100,
            retry_timeout: 1000,
            max_file_size: 2000,
            #[cfg(feature = "encryption")]
            private_key,
            #[cfg(feature = "encryption")]
            server_public_key,
            #[cfg(feature = "encryption")]
            encryption_level: _encryption_level.to_string().parse().unwrap(),
            #[cfg(feature = "encryption")]
            known_hosts: None,
            window_size,
            allow_server_port_change: false,
        };

        let local_file = "from".parse().unwrap();
        let remote_file = "to".parse().ok();
        let create_reader =
            |_path: &FilePath| Ok((Some(bytes.len() as u64), CursorReader::new(bytes.clone())));

        start_send(
            local_file,
            remote_file,
            cli_config,
            create_reader,
            false,
            false,
        )
    }

    fn start_receive_file(
        server_port: u16,
        _encryption_level: EncryptionLevel,
        window_size: u64,
        bytes: Arc<Mutex<Cursor<Vec<u8>>>>,
        #[cfg(feature = "encryption")] server_public_key: Option<ShortString>,
        #[cfg(feature = "encryption")] private_key: Option<ShortString>,
    ) -> BinResult<usize> {
        let cli_config = ClientCliConfig {
            endpoint: format!("127.0.0.1:{server_port}").parse().unwrap(),
            listen: "127.0.0.1:0".parse().unwrap(),
            request_timeout: 1000,
            block_size: 100,
            retry_timeout: 1000,
            max_file_size: 2000,
            #[cfg(feature = "encryption")]
            private_key,
            #[cfg(feature = "encryption")]
            server_public_key,
            #[cfg(feature = "encryption")]
            encryption_level: _encryption_level.to_string().parse().unwrap(),
            #[cfg(feature = "encryption")]
            known_hosts: None,
            window_size,
            allow_server_port_change: false,
        };

        let local_file = "from".parse().ok();
        let remote_file = "to".parse().unwrap();
        let create_writer = |_path: &FilePath| Ok(MutexWriter::new(bytes.clone()));

        start_receive(local_file, remote_file, cli_config, create_writer)
    }

    fn start_server(
        server_port: u16,
        read_bytes: Vec<u8>,
        write_bytes: Arc<Mutex<Cursor<Vec<u8>>>>,
        private_key: Option<PrivateKey>,
        authorized_keys: Option<AuthorizedKeys>,
    ) -> DefaultBoxedResult {
        let listen: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
        #[cfg(not(feature = "std"))]
        let listen = std_to_socket_addr(listen);
        let config = ServerConfig {
            listen,
            directory: "/tmp".parse().unwrap(),
            allow_overwrite: false,
            request_timeout: Duration::from_millis(1000),
            max_connections: 10,
            max_file_size: 2000,
            max_block_size: MAX_DATA_BLOCK_SIZE,
            authorized_keys,
            private_key,
            required_full_encryption: false,
            require_server_port_change: false,
            max_window_size: 4,
            prefer_seek: false,
        };

        let create_reader = |_path: &FilePath, _config: &ServerConfig| {
            Ok((
                Some(read_bytes.len() as u64),
                CursorReader::new(read_bytes.clone()),
            ))
        };
        let create_writer =
            |_path: &FilePath, _config: &ServerConfig| Ok(MutexWriter::new(write_bytes.clone()));

        server(
            config,
            create_reader,
            create_writer,
            create_socket,
            create_bound_socket,
            instant_callback,
            OsRng,
        )
    }

    struct MutexWriter {
        cursor: Arc<Mutex<Cursor<Vec<u8>>>>,
    }

    impl MutexWriter {
        fn new(cursor: Arc<Mutex<Cursor<Vec<u8>>>>) -> Self {
            Self { cursor }
        }
    }

    impl io::Write for MutexWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            #[allow(unused_imports)]
            use std::io::Write;
            self.cursor.lock().unwrap().write(buf).unwrap();
            Ok(buf.len())
        }

        fn write_fmt(
            &mut self,
            _: core::fmt::Arguments<'_>,
        ) -> Result<(), tftp::std_compat::io::Error> {
            todo!()
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl io::Seek for MutexWriter {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            #[allow(unused_imports)]
            use std::io::Seek;
            let pos = match pos {
                io::SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
                io::SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
                io::SeekFrom::End(p) => std::io::SeekFrom::End(p),
            };
            self.cursor.lock().unwrap().seek(pos).map_err(|_| {
                tftp::std_compat::io::Error::from(tftp::std_compat::io::ErrorKind::Other)
            })
        }
    }

    fn get_port() -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    }

    #[cfg(feature = "std")]
    type CursorReader = Cursor<Vec<u8>>;

    #[cfg(not(feature = "std"))]
    struct CursorReader {
        cursor: Cursor<Vec<u8>>,
    }

    #[cfg(not(feature = "std"))]
    impl CursorReader {
        pub fn new(bytes: Vec<u8>) -> Self {
            Self {
                cursor: Cursor::new(bytes),
            }
        }
    }

    #[cfg(not(feature = "std"))]
    impl io::Read for CursorReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            #[allow(unused_imports)]
            use std::io::Read;
            self.cursor
                .read(buf)
                .map_err(|_| io::Error::from(io::ErrorKind::Other))
        }
    }

    #[cfg(not(feature = "std"))]
    impl io::Seek for CursorReader {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            #[allow(unused_imports)]
            use std::io::Seek;
            let pos = match pos {
                io::SeekFrom::Start(p) => std::io::SeekFrom::Start(p),
                io::SeekFrom::Current(p) => std::io::SeekFrom::Current(p),
                io::SeekFrom::End(p) => std::io::SeekFrom::End(p),
            };
            self.cursor.seek(pos).map_err(|_| {
                tftp::std_compat::io::Error::from(tftp::std_compat::io::ErrorKind::Other)
            })
        }
    }
}
