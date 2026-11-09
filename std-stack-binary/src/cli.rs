use core::fmt::Display;
use core::fmt::Formatter;
use core::iter::Peekable;
use core::str::FromStr;

use log::LevelFilter;
use tftp_dus::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use tftp_dus::config::DEFAULT_WINDOW_SIZE;
use tftp_dus::config::EXTENSION_BLOCK_SIZE_MAX;
use tftp_dus::config::EXTENSION_BLOCK_SIZE_MIN;
use tftp_dus::config::EXTENSION_TIMEOUT_SIZE_MAX;
use tftp_dus::config::EXTENSION_WINDOW_SIZE_MIN;
use tftp_dus::config::MAX_BLOCKS_FOR_MULTI_READER;
use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::config::PREFERRED_DATA_BLOCK_SIZE;
use tftp_dus::features::ENCRYPTION_ENABLED;

pub const USAGE: &str = "\
tftp client and server that never allocates on the heap (Linux and macOS)

Usage: tftp-dus-stack-only [-v LEVEL] <COMMAND>

Commands:
  send ENDPOINT FILE     [-r|--remote-path PATH] [--prefer-seek] [client options]
  receive ENDPOINT FILE  [--local-path PATH] [client options]
  server LISTEN DIR      [server options]

Addresses must be IP literals: resolving hostnames requires the heap.

Options:
  -v, --verbosity LEVEL  off, error, warn, info, debug, trace [default: info]
  -h, --help             Print help
  -V, --version          Print version

Client options:
  -l, --listen ADDR, --request-timeout MS, --block-size N, --window-size N,
  --retry-timeout MS, --max-file-size BYTES, --allow-server-port-change,
  --encryption-level LEVEL, --private-key KEY, --server-public-key KEY,
  --known-hosts FILE, --encryption-key KEY

Server options:
  -a, --allow-overwrite, --max-connections N, --max-window-size N,
  --request-timeout MS, --max-file-size BYTES, --max-block-size N,
  --max-directory-depth N, --prefer-seek, --authorized-keys FILE,
  --private-key KEY, --require-full-encryption [BOOL],
  --require-server-port-change [BOOL], --error-to-authorized-only [BOOL]
";

#[derive(Debug, PartialEq, Eq)]
pub struct UsageError<'a> {
    pub message: &'static str,
    pub argument: &'a str,
}

impl Display for UsageError<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.message, self.argument)
    }
}

type CliResult<'a, T> = Result<T, UsageError<'a>>;

fn usage_error<'a, T>(message: &'static str, argument: &'a str) -> CliResult<'a, T> {
    Err(UsageError { message, argument })
}

#[derive(Debug)]
pub struct ClientArgs<'a> {
    pub endpoint: &'a str,
    pub listen: Option<&'a str>,
    pub request_timeout: u64,
    pub block_size: u64,
    pub window_size: u64,
    pub retry_timeout: u64,
    pub max_file_size: u64,
    pub allow_server_port_change: bool,
    pub encryption_level: &'a str,
    pub private_key: Option<&'a str>,
    pub server_public_key: Option<&'a str>,
    pub known_hosts: Option<&'a str>,
    pub encryption_key: Option<&'a str>,
}

#[derive(Debug)]
pub struct ServerArgs<'a> {
    pub listen: &'a str,
    pub directory: &'a str,
    pub allow_overwrite: bool,
    pub max_connections: u64,
    pub max_window_size: u64,
    pub request_timeout: u64,
    pub max_file_size: u64,
    pub max_block_size: u64,
    pub max_directory_depth: u64,
    pub prefer_seek: bool,
    pub authorized_keys: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub require_full_encryption: Option<bool>,
    pub require_server_port_change: bool,
    pub error_to_authorized_only: Option<bool>,
}

#[derive(Debug)]
pub enum Command<'a> {
    Send {
        config: ClientArgs<'a>,
        local_path: &'a str,
        remote_path: Option<&'a str>,
        prefer_seek: bool,
    },
    Receive {
        config: ClientArgs<'a>,
        local_path: Option<&'a str>,
        remote_path: &'a str,
    },
    Server(ServerArgs<'a>),
    Help,
    Version,
}

#[derive(Debug)]
pub struct Args<'a> {
    pub verbosity: LevelFilter,
    pub command: Command<'a>,
}

enum Token<'a> {
    Flag {
        name: &'a str,
        inline: Option<&'a str>,
    },
    Positional(&'a str),
}

struct Tokens<'a, I: Iterator<Item = &'a str>> {
    args: Peekable<I>,
    positional_only: bool,
}

impl<'a, I: Iterator<Item = &'a str>> Tokens<'a, I> {
    fn next(&mut self) -> Option<Token<'a>> {
        let arg = self.args.next()?;
        if self.positional_only {
            return Some(Token::Positional(arg));
        }
        if arg == "--" {
            self.positional_only = true;
            return self.next();
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            return Some(Token::Flag { name, inline });
        }
        match arg.strip_prefix('-') {
            Some(short) if !short.is_empty() => Some(Token::Flag {
                name: short,
                inline: None,
            }),
            _ => Some(Token::Positional(arg)),
        }
    }

    fn value(&mut self, name: &'a str, inline: Option<&'a str>) -> CliResult<'a, &'a str> {
        match inline.or_else(|| self.args.next()) {
            Some(value) => Ok(value),
            None => usage_error("missing value for option", name),
        }
    }

    fn number(
        &mut self,
        name: &'a str,
        inline: Option<&'a str>,
        range: core::ops::RangeInclusive<u64>,
    ) -> CliResult<'a, u64> {
        let value = self.value(name, inline)?;
        match value.parse() {
            Ok(number) if range.contains(&number) => Ok(number),
            _ => usage_error("value is invalid or out of range", value),
        }
    }

    /// `--flag`, `--flag=false` and `--flag false` are all accepted.
    fn optional_bool(&mut self, inline: Option<&'a str>) -> CliResult<'a, bool> {
        if let Some(value) = inline {
            return match bool::from_str(value) {
                Ok(parsed) => Ok(parsed),
                Err(_) => usage_error("expected true or false", value),
            };
        }
        match self.args.peek().and_then(|v| bool::from_str(v).ok()) {
            Some(parsed) => {
                self.args.next();
                Ok(parsed)
            }
            None => Ok(true),
        }
    }
}

fn reject_value<'a>(name: &'a str, inline: Option<&'a str>) -> CliResult<'a, bool> {
    match inline {
        Some(_) => usage_error("option does not take a value", name),
        None => Ok(true),
    }
}

fn client_defaults<'a>() -> ClientArgs<'a> {
    ClientArgs {
        endpoint: "",
        listen: None,
        request_timeout: 15000,
        block_size: PREFERRED_DATA_BLOCK_SIZE as u64,
        window_size: DEFAULT_WINDOW_SIZE as u64,
        retry_timeout: DEFAULT_RETRY_PACKET_TIMEOUT.as_millis() as u64,
        max_file_size: 10485760,
        allow_server_port_change: false,
        encryption_level: "optional-protocol",
        private_key: None,
        server_public_key: None,
        known_hosts: None,
        encryption_key: None,
    }
}

/// Returns false when the flag is not a shared client option.
fn parse_client_flag<'a, I: Iterator<Item = &'a str>>(
    config: &mut ClientArgs<'a>,
    tokens: &mut Tokens<'a, I>,
    name: &'a str,
    inline: Option<&'a str>,
) -> CliResult<'a, bool> {
    let retry_min = DEFAULT_RETRY_PACKET_TIMEOUT.as_millis() as u64;
    match name {
        "l" | "listen" => config.listen = Some(tokens.value(name, inline)?),
        "request-timeout" => config.request_timeout = tokens.number(name, inline, 0..=u64::MAX)?,
        "block-size" => {
            config.block_size = tokens.number(
                name,
                inline,
                EXTENSION_BLOCK_SIZE_MIN as u64..=EXTENSION_BLOCK_SIZE_MAX as u64,
            )?
        }
        "window-size" => {
            config.window_size = tokens.number(
                name,
                inline,
                EXTENSION_WINDOW_SIZE_MIN as u64..=MAX_BLOCKS_FOR_MULTI_READER as u64,
            )?
        }
        "retry-timeout" => {
            config.retry_timeout = tokens.number(
                name,
                inline,
                retry_min..=EXTENSION_TIMEOUT_SIZE_MAX as u64 * 1000 - 1,
            )?
        }
        "max-file-size" => config.max_file_size = tokens.number(name, inline, 0..=u64::MAX)?,
        "allow-server-port-change" => config.allow_server_port_change = reject_value(name, inline)?,
        "encryption-level" if ENCRYPTION_ENABLED => {
            config.encryption_level = tokens.value(name, inline)?
        }
        "private-key" if ENCRYPTION_ENABLED => {
            config.private_key = Some(tokens.value(name, inline)?)
        }
        "server-public-key" if ENCRYPTION_ENABLED => {
            config.server_public_key = Some(tokens.value(name, inline)?)
        }
        "known-hosts" if ENCRYPTION_ENABLED => {
            config.known_hosts = Some(tokens.value(name, inline)?)
        }
        "encryption-key" if ENCRYPTION_ENABLED => {
            config.encryption_key = Some(tokens.value(name, inline)?)
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn is_help(name: &str) -> bool {
    matches!(name, "h" | "help")
}

fn parse_send<'a, I: Iterator<Item = &'a str>>(
    tokens: &mut Tokens<'a, I>,
) -> CliResult<'a, Command<'a>> {
    let mut config = client_defaults();
    let (mut endpoint, mut local_path, mut remote_path) = (None, None, None);
    #[allow(unused_mut)]
    let mut prefer_seek = false;
    while let Some(token) = tokens.next() {
        match token {
            Token::Positional(value) if endpoint.is_none() => endpoint = Some(value),
            Token::Positional(value) if local_path.is_none() => local_path = Some(value),
            Token::Positional(value) => return usage_error("unexpected argument", value),
            Token::Flag { name, .. } if is_help(name) => return Ok(Command::Help),
            Token::Flag { name, inline } => match name {
                "r" | "remote-path" => remote_path = Some(tokens.value(name, inline)?),
                #[cfg(feature = "seek")]
                "prefer-seek" => prefer_seek = reject_value(name, inline)?,
                _ if parse_client_flag(&mut config, tokens, name, inline)? => (),
                _ => return usage_error("unknown option", name),
            },
        }
    }
    let (Some(endpoint), Some(local_path)) = (endpoint, local_path) else {
        return usage_error("missing required arguments", "send ENDPOINT FILE");
    };
    config.endpoint = endpoint;
    Ok(Command::Send {
        config,
        local_path,
        remote_path,
        prefer_seek,
    })
}

fn parse_receive<'a, I: Iterator<Item = &'a str>>(
    tokens: &mut Tokens<'a, I>,
) -> CliResult<'a, Command<'a>> {
    let mut config = client_defaults();
    let (mut endpoint, mut remote_path, mut local_path) = (None, None, None);
    while let Some(token) = tokens.next() {
        match token {
            Token::Positional(value) if endpoint.is_none() => endpoint = Some(value),
            Token::Positional(value) if remote_path.is_none() => remote_path = Some(value),
            Token::Positional(value) => return usage_error("unexpected argument", value),
            Token::Flag { name, .. } if is_help(name) => return Ok(Command::Help),
            Token::Flag { name, inline } => match name {
                "local-path" => local_path = Some(tokens.value(name, inline)?),
                _ if parse_client_flag(&mut config, tokens, name, inline)? => (),
                _ => return usage_error("unknown option", name),
            },
        }
    }
    let (Some(endpoint), Some(remote_path)) = (endpoint, remote_path) else {
        return usage_error("missing required arguments", "receive ENDPOINT FILE");
    };
    config.endpoint = endpoint;
    Ok(Command::Receive {
        config,
        local_path,
        remote_path,
    })
}

fn parse_server<'a, I: Iterator<Item = &'a str>>(
    tokens: &mut Tokens<'a, I>,
) -> CliResult<'a, Command<'a>> {
    let mut config = ServerArgs {
        listen: "",
        directory: "",
        allow_overwrite: false,
        max_connections: MAX_CLIENTS as u64,
        max_window_size: MAX_BLOCKS_FOR_MULTI_READER as u64,
        request_timeout: 15000,
        max_file_size: 104857600,
        max_block_size: PREFERRED_DATA_BLOCK_SIZE as u64,
        max_directory_depth: 10,
        prefer_seek: false,
        authorized_keys: None,
        private_key: None,
        require_full_encryption: None,
        require_server_port_change: false,
        error_to_authorized_only: None,
    };
    let (mut listen, mut directory) = (None, None);
    while let Some(token) = tokens.next() {
        match token {
            Token::Positional(value) if listen.is_none() => listen = Some(value),
            Token::Positional(value) if directory.is_none() => directory = Some(value),
            Token::Positional(value) => return usage_error("unexpected argument", value),
            Token::Flag { name, .. } if is_help(name) => return Ok(Command::Help),
            Token::Flag { name, inline } => match name {
                "a" | "allow-overwrite" => config.allow_overwrite = reject_value(name, inline)?,
                "max-connections" => {
                    config.max_connections = tokens.number(name, inline, 1..=MAX_CLIENTS as u64)?
                }
                "max-window-size" => {
                    config.max_window_size =
                        tokens.number(name, inline, 1..=MAX_BLOCKS_FOR_MULTI_READER as u64)?
                }
                "request-timeout" => {
                    config.request_timeout = tokens.number(name, inline, 0..=u64::MAX)?
                }
                "max-file-size" => {
                    config.max_file_size = tokens.number(name, inline, 0..=u64::MAX)?
                }
                "max-block-size" => {
                    config.max_block_size = tokens.number(
                        name,
                        inline,
                        EXTENSION_BLOCK_SIZE_MIN as u64..=EXTENSION_BLOCK_SIZE_MAX as u64,
                    )?
                }
                "max-directory-depth" => {
                    config.max_directory_depth = tokens.number(name, inline, 0..=u16::MAX as u64)?
                }
                "require-server-port-change" => {
                    config.require_server_port_change = tokens.optional_bool(inline)?
                }
                #[cfg(feature = "seek")]
                "prefer-seek" => config.prefer_seek = reject_value(name, inline)?,
                "authorized-keys" if ENCRYPTION_ENABLED => {
                    config.authorized_keys = Some(tokens.value(name, inline)?)
                }
                "private-key" if ENCRYPTION_ENABLED => {
                    config.private_key = Some(tokens.value(name, inline)?)
                }
                "require-full-encryption" if ENCRYPTION_ENABLED => {
                    config.require_full_encryption = Some(tokens.optional_bool(inline)?)
                }
                "error-to-authorized-only" if ENCRYPTION_ENABLED => {
                    config.error_to_authorized_only = Some(tokens.optional_bool(inline)?)
                }
                _ => return usage_error("unknown option", name),
            },
        }
    }
    let (Some(listen), Some(directory)) = (listen, directory) else {
        return usage_error("missing required arguments", "server LISTEN DIR");
    };
    config.listen = listen;
    config.directory = directory;
    Ok(Command::Server(config))
}

pub fn parse<'a>(args: impl Iterator<Item = &'a str>) -> CliResult<'a, Args<'a>> {
    let mut tokens = Tokens {
        args: args.peekable(),
        positional_only: false,
    };
    let mut verbosity = LevelFilter::Info;
    while let Some(token) = tokens.next() {
        let command = match token {
            Token::Flag { name, inline } => match name {
                "v" | "verbosity" => {
                    let value = tokens.value(name, inline)?;
                    let Ok(level) = LevelFilter::from_str(value) else {
                        return usage_error("invalid verbosity", value);
                    };
                    verbosity = level;
                    continue;
                }
                "h" | "help" => Command::Help,
                "V" | "version" => Command::Version,
                _ => return usage_error("unknown option", name),
            },
            Token::Positional("send") => parse_send(&mut tokens)?,
            Token::Positional("receive") => parse_receive(&mut tokens)?,
            Token::Positional("server") => parse_server(&mut tokens)?,
            Token::Positional(value) => return usage_error("unknown command", value),
        };
        return Ok(Args { verbosity, command });
    }
    Ok(Args {
        verbosity,
        command: Command::Help,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_line(line: &str) -> CliResult<'_, Args<'_>> {
        parse(line.split_whitespace())
    }

    #[test]
    fn test_parse_send() {
        let args =
            parse_line("-v debug send 127.0.0.1:69 /a -r b --block-size=512 -l 0.0.0.0:0").unwrap();
        assert_eq!(args.verbosity, LevelFilter::Debug);
        let Command::Send {
            config,
            local_path,
            remote_path,
            ..
        } = args.command
        else {
            panic!("expected send");
        };
        assert_eq!(config.endpoint, "127.0.0.1:69");
        assert_eq!(config.block_size, 512);
        assert_eq!(config.listen, Some("0.0.0.0:0"));
        assert_eq!(local_path, "/a");
        assert_eq!(remote_path, Some("b"));
    }

    #[test]
    fn test_parse_receive_defaults() {
        let args = parse_line("receive 127.0.0.1 file").unwrap();
        let Command::Receive { config, .. } = args.command else {
            panic!("expected receive");
        };
        assert_eq!(config.window_size, DEFAULT_WINDOW_SIZE as u64);
        assert_eq!(config.request_timeout, 15000);
    }

    #[test]
    fn test_parse_server_optional_bool() {
        for (line, expected) in [
            ("server 127.0.0.1:69 /d --require-server-port-change", true),
            (
                "server 127.0.0.1:69 /d --require-server-port-change false",
                false,
            ),
            (
                "server 127.0.0.1:69 /d --require-server-port-change=false",
                false,
            ),
            ("server 127.0.0.1:69 /d", false),
        ] {
            let Command::Server(config) = parse_line(line).unwrap().command else {
                panic!("expected server");
            };
            assert_eq!(config.require_server_port_change, expected, "{line}");
        }
    }

    #[test]
    fn test_parse_errors() {
        let data = [
            ("nope", "unknown command"),
            ("send 127.0.0.1", "missing required arguments"),
            ("send 127.0.0.1 a b", "unexpected argument"),
            ("send 127.0.0.1 a --bad", "unknown option"),
            ("send 127.0.0.1 a --block-size", "missing value for option"),
            (
                "send 127.0.0.1 a --block-size 1",
                "value is invalid or out of range",
            ),
            (
                "server 127.0.0.1 /d --max-connections 0",
                "value is invalid or out of range",
            ),
            ("server 127.0.0.1 /d -a=1 --a=1", "unknown option"),
            ("-v loud send", "invalid verbosity"),
        ];
        for (line, message) in data {
            assert_eq!(parse_line(line).unwrap_err().message, message, "{line}");
        }
    }

    #[test]
    fn test_parse_help_and_empty() {
        assert!(matches!(parse_line("").unwrap().command, Command::Help));
        assert!(matches!(
            parse_line("--help").unwrap().command,
            Command::Help
        ));
        assert!(matches!(
            parse_line("-V").unwrap().command,
            Command::Version
        ));
        assert!(matches!(
            parse_line("send -h").unwrap().command,
            Command::Help
        ));
    }
}
