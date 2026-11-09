use core::str::FromStr;

use clap::Parser;
use clap::Subcommand;
use clap::ValueHint;
use tftp_dus::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use tftp_dus::config::DEFAULT_WINDOW_SIZE;
use tftp_dus::config::EXTENSION_BLOCK_SIZE_MAX;
use tftp_dus::config::EXTENSION_BLOCK_SIZE_MIN;
use tftp_dus::config::EXTENSION_TIMEOUT_SIZE_MAX;
use tftp_dus::config::EXTENSION_WINDOW_SIZE_MIN;
use tftp_dus::config::MAX_BLOCKS_FOR_MULTI_READER;
use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::config::PREFERRED_DATA_BLOCK_SIZE;
use tftp_dus::types::DefaultString;
use tftp_dus::types::FilePath;
use tftp_dus::types::ShortString;

use crate::encryption_args::ClientEncryptionArgs;
use crate::encryption_args::ServerEncryptionArgs;

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

    #[arg(short, long, help = "defaults to ivp4 0.0.0.0:0 or ipv6 ::0 based on endpoint", value_parser = try_from_str::<DefaultString>, value_hint = ValueHint::Hostname)]
    pub listen: Option<DefaultString>,

    #[arg(
        long,
        default_value_t = 15000,
        help = "Request time out in milliseconds"
    )]
    pub request_timeout: u64,

    #[arg(long, default_value_t = PREFERRED_DATA_BLOCK_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_BLOCK_SIZE_MIN as u64)..=(EXTENSION_BLOCK_SIZE_MAX as u64)))]
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

    #[command(flatten)]
    pub encryption: ClientEncryptionArgs,

    #[arg(long)]
    pub allow_server_port_change: bool,
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

    #[arg(long, default_value_t = PREFERRED_DATA_BLOCK_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_BLOCK_SIZE_MIN as u64)..=(EXTENSION_BLOCK_SIZE_MAX as u64)))]
    pub max_block_size: u64,

    #[command(flatten)]
    pub encryption: ServerEncryptionArgs,

    #[arg(
        long,
        help = "Require that server will change a port after receiving initial packet. This is enabled for windows server",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    pub require_server_port_change: Option<bool>,

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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_max_connections(extra: &[&str]) -> Result<u64, clap::Error> {
        let arguments = ["tftp-dus", "server", "127.0.0.1:69", "/tmp"];
        let args = Args::try_parse_from(arguments.iter().chain(extra))?;
        match args.command {
            Commands::Server(config) => Ok(config.max_connections),
            _ => panic!("expected the server command"),
        }
    }

    #[test]
    fn test_default_max_connections() {
        assert_eq!(parse_max_connections(&[]).unwrap(), MAX_CLIENTS as u64);
    }

    #[test]
    fn test_max_connections_can_be_raised_to_the_limit() {
        let limit = MAX_CLIENTS.to_string();
        let parsed = parse_max_connections(&["--max-connections", &limit]);
        assert_eq!(parsed.unwrap(), MAX_CLIENTS as u64);
    }
}
