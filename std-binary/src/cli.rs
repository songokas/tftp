use clap::Parser;
use clap::Subcommand;
use clap::ValueHint;
use core::str::FromStr;
use tftp::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use tftp::config::DEFAULT_WINDOW_SIZE;
use tftp::config::EXTENSION_BLOCK_SIZE_MIN;
use tftp::config::EXTENSION_TIMEOUT_SIZE_MAX;
use tftp::config::EXTENSION_WINDOW_SIZE_MIN;
use tftp::config::MAX_BLOCKS_FOR_MULTI_READER;
use tftp::config::MAX_CLIENTS;
use tftp::config::MAX_DATA_BLOCK_SIZE;
use tftp::types::DefaultString;
use tftp::types::FilePath;
use tftp::types::ShortString;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
    #[arg(short, long, default_value = "info", value_parser = try_from_str::<DefaultString>)]
    pub verbosity: DefaultString,
}

#[derive(Parser, Debug, Clone)]
pub struct ClientCliConfig {
    #[arg(value_parser = try_from_str::<DefaultString>, value_hint = ValueHint::Hostname)]
    pub endpoint: DefaultString,

    #[arg(short, long, default_value = "0.0.0.0:0", value_parser = try_from_str::<DefaultString>, value_hint = ValueHint::Hostname)]
    pub listen: DefaultString,

    #[arg(
        long,
        default_value_t = 15000,
        help = "Request time out in milliseconds"
    )]
    pub request_timeout: u64,

    #[arg(long, default_value_t = MAX_DATA_BLOCK_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_BLOCK_SIZE_MIN as u64)..=(MAX_DATA_BLOCK_SIZE as u64)))]
    pub block_size: u64,

    #[arg(long, default_value_t = DEFAULT_WINDOW_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_WINDOW_SIZE_MIN as u64)..=(MAX_BLOCKS_FOR_MULTI_READER as u64)))]
    pub window_size: u64,

    #[arg(
        long,
        default_value_t = DEFAULT_RETRY_PACKET_TIMEOUT.as_millis() as u64,
        value_parser = clap::value_parser!(u64).range((DEFAULT_RETRY_PACKET_TIMEOUT.as_millis() as u64)..(EXTENSION_TIMEOUT_SIZE_MAX as u64 * 1000)),
        help = "Resend packet after timeout in ms"
    )]
    pub retry_timeout: u64,

    #[arg(long, default_value_t = 10485760, help = "Max file size to receive")]
    pub max_file_size: u64,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        default_value = "optional-protocol",
        help = "Available values protocol, data, optional-data, optional-protocol, none",
        value_parser = try_from_str::<ShortString>,
    )]
    pub encryption_level: ShortString,

    #[cfg(feature = "encryption")]
    #[arg(long, help = "Base64 encoded private key to use: value or FILE", value_parser = try_from_str::<ShortString>)]
    pub private_key: Option<ShortString>,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        help = "Base64 encoded remote server public key to use for encryption",
        value_parser = try_from_str::<ShortString>,
    )]
    pub server_public_key: Option<ShortString>,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        help = "Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line",
        value_hint = ValueHint::FilePath,
        value_parser = try_from_str::<FilePath>,
    )]
    pub known_hosts: Option<FilePath>,

    #[arg(long)]
    pub allow_server_port_change: bool,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        help = "Encrypt/decrypt file when sending/receiving. Key should be 32 chars long",
        value_parser = try_from_str::<ShortString>,
    )]
    pub encryption_key: Option<ShortString>,
}

#[derive(Parser, Debug, Clone)]
pub struct ServerCliConfig {
    #[arg(value_parser = try_from_str::<DefaultString>, value_hint = ValueHint::Hostname)]
    pub listen: DefaultString,

    #[arg(value_parser = try_from_str::<FilePath>, value_hint = ValueHint::DirPath)]
    pub directory: FilePath,

    #[arg(short, long)]
    pub allow_overwrite: bool,

    #[arg(long, default_value_t = MAX_CLIENTS as u64, value_parser = clap::value_parser!(u64).range(1..=(MAX_CLIENTS as u64)))]
    pub max_connections: u64,

    #[arg(long, default_value_t = MAX_BLOCKS_FOR_MULTI_READER as u64, value_parser = clap::value_parser!(u64).range(1..=(MAX_BLOCKS_FOR_MULTI_READER) as u64))]
    pub max_window_size: u64,

    #[arg(
        long,
        default_value_t = 15000,
        help = "Request time out in milliseconds"
    )]
    pub request_timeout: u64,

    #[arg(
        long,
        default_value_t = 104857600,
        help = "Max file size to receive in bytes"
    )]
    pub max_file_size: u64,

    #[arg(long, default_value_t = MAX_DATA_BLOCK_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_BLOCK_SIZE_MIN as u64)..=(MAX_DATA_BLOCK_SIZE as u64)))]
    pub max_block_size: u64,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        help = "Path to a file with authorized public keys. Each line contains base64(public key)",
        value_parser = try_from_str::<FilePath>,
        value_hint = ValueHint::FilePath,
    )]
    pub authorized_keys: Option<FilePath>,

    #[cfg(feature = "encryption")]
    #[arg(long, help = "Base64 encoded private key to use: value or FILE", value_parser = try_from_str::<ShortString>)]
    pub private_key: Option<ShortString>,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        help = "Require that connections be fully encrypted. This is enabled if authorized keys are provided"
    )]
    pub required_full_encryption: Option<bool>,

    #[arg(long)]
    pub require_server_port_change: bool,

    #[cfg(feature = "seek")]
    #[arg(long)]
    pub prefer_seek: bool,

    #[arg(long, help = "Retrieving specified file provides directory list", value_parser = try_from_str::<ShortString>)]
    pub directory_list: Option<ShortString>,

    #[arg(long, default_value_t = 10, help = "Maximum directory depth")]
    pub max_directory_depth: u16,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Send {
        #[clap(flatten)]
        config: ClientCliConfig,

        #[arg(value_name = "FILE", value_parser = try_from_str::<FilePath>, value_hint = ValueHint::FilePath)]
        local_path: FilePath,

        #[arg(short, long, value_parser = try_from_str::<FilePath>)]
        remote_path: Option<FilePath>,

        #[cfg(feature = "seek")]
        #[arg(long)]
        prefer_seek: bool,
    },
    #[cfg(feature = "sync")]
    Sync {
        #[clap(flatten)]
        config: ClientCliConfig,

        #[arg(
            long,
            help = "Start sending the file once its created. Default is to send once file is written"
        )]
        start_on_create: bool,

        #[arg(
            long,
            default_value_t = 1000,
            help = "How long to block before reading the file in milliseconds (only for --start-on-create)"
        )]
        block_duration: u64,

        #[arg(value_name = "DIRECTORY", value_parser = try_from_str::<FilePath>, value_hint = ValueHint::DirPath)]
        dir_path: Option<FilePath>,
    },

    Receive {
        #[clap(flatten)]
        config: ClientCliConfig,

        #[arg(long, value_parser = try_from_str::<FilePath>, value_hint = ValueHint::FilePath)]
        local_path: Option<FilePath>,

        #[arg(value_name = "FILE", value_parser = try_from_str::<FilePath>)]
        remote_path: FilePath,
    },

    Server(ServerCliConfig),
}

fn try_from_str<T: FromStr>(arg: &str) -> Result<T, &'static str> {
    T::from_str(arg).map_err(|_| "Failed to parse")
}
