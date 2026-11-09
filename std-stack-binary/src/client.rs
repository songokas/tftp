use core::net::IpAddr;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use core::time::Duration;

use log::debug;
use rand::rngs::OsRng;
use tftp_binary_common::client::connection_options;
use tftp_binary_common::keys::handle_hosts_file;
use tftp_binary_common::keys::load_encryption_key;
use tftp_binary_common::keys::load_private_key;
use tftp_binary_common::keys::load_remote_public_key;
use tftp_binary_common::path::file_name;
use tftp_dus::client::receive_file;
use tftp_dus::client::send_file;
use tftp_dus::client::ClientConfig;
use tftp_dus::config::ConnectionOptions;
use tftp_dus::types::FilePath;

use crate::cli::ClientArgs;
use crate::error::BinError;
use crate::error::BinResult;
use crate::files::create_reader;
use crate::files::create_writer;
use crate::socket::create_socket;
use crate::time::instant_callback;

const DEFAULT_TFTP_PORT: u16 = 69;

/// Hostnames are rejected because getaddrinfo and std's lookup allocate.
///
/// `::1:9000` is host `::1` port 9000 as it is for std-binary, even though the
/// whole text is also a valid IPv6 address.
pub fn parse_endpoint(endpoint: &str) -> BinResult<SocketAddr> {
    if let Ok(address) = endpoint.parse() {
        return Ok(address);
    }
    if let Some((host, port)) = endpoint.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (host.parse::<IpAddr>(), port.parse()) {
            return Ok(SocketAddr::new(ip, port));
        }
    }
    match endpoint.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, DEFAULT_TFTP_PORT)),
        Err(_) => Err("Endpoint must be an IP address with optional port".into()),
    }
}

pub fn parse_file_path(path: &str) -> BinResult<FilePath> {
    path.parse().map_err(|_| "File path is too long".into())
}

fn default_listen(endpoint: SocketAddr) -> SocketAddr {
    let ip = match endpoint {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0)
}

fn options(args: &ClientArgs<'_>, file_size: Option<u64>) -> BinResult<ConnectionOptions> {
    Ok(connection_options(
        args.encryption_level,
        args.block_size,
        args.window_size,
        args.retry_timeout,
        file_size,
    )?)
}

fn client_config(
    args: &ClientArgs<'_>,
    listen: SocketAddr,
    endpoint: SocketAddr,
    prefer_seek: bool,
) -> BinResult<ClientConfig> {
    Ok(ClientConfig {
        listen,
        endpoint,
        request_timeout: Duration::from_millis(args.request_timeout),
        max_file_size: args.max_file_size,
        private_key: load_private_key(args.private_key)?,
        remote_public_key: load_remote_public_key(
            args.server_public_key,
            args.known_hosts,
            args.endpoint,
        )?,
        allow_server_port_change: args.allow_server_port_change,
        prefer_seek,
        encryption_key: load_encryption_key(args.encryption_key)?,
    })
}

fn addresses(args: &ClientArgs<'_>) -> BinResult<(SocketAddr, SocketAddr)> {
    let endpoint = parse_endpoint(args.endpoint)?;
    let listen = match args.listen {
        Some(listen) => listen
            .parse()
            .map_err(|_| BinError::Message("Listen must be an IP address with port"))?,
        None => default_listen(endpoint),
    };
    Ok((listen, endpoint))
}

pub fn start_send(
    args: &ClientArgs<'_>,
    local_path: &str,
    remote_path: Option<&str>,
    prefer_seek: bool,
) -> BinResult<usize> {
    let (listen, endpoint) = addresses(args)?;
    let socket = create_socket(listen, 1, false, 1)?;
    let options = options(args, None)?;
    let local_path = parse_file_path(local_path)?;
    let remote_path = match remote_path {
        Some(path) => parse_file_path(path)?,
        None => file_name(&local_path)?,
    };
    let config = client_config(args, listen, endpoint, prefer_seek)?;
    let result = match config.encryption_key {
        #[cfg(feature = "encryption")]
        Some(key) => {
            let block_size = options.block_size_with_encryption();
            send_file(
                config,
                local_path,
                remote_path,
                options,
                tftp_binary_common::keys::create_encryption_reader(
                    key,
                    OsRng,
                    block_size,
                    create_reader,
                ),
                socket,
                instant_callback,
                OsRng,
            )
        }
        _ => send_file(
            config,
            local_path,
            remote_path,
            options,
            create_reader,
            socket,
            instant_callback,
            OsRng,
        ),
    };
    let (total, remote_key) = result?;
    debug!("Client total sent {total}");
    handle_hosts_file(args.known_hosts, remote_key, args.endpoint);
    Ok(total)
}

pub fn start_receive(
    args: &ClientArgs<'_>,
    local_path: Option<&str>,
    remote_path: &str,
) -> BinResult<usize> {
    let (listen, endpoint) = addresses(args)?;
    let socket = create_socket(listen, 1, false, 1)?;
    let options = options(args, Some(0))?;
    let remote_path = parse_file_path(remote_path)?;
    let local_path = match local_path {
        Some(path) => parse_file_path(path)?,
        None => file_name(&remote_path)?,
    };
    let config = client_config(args, listen, endpoint, false)?;
    let result = match config.encryption_key {
        #[cfg(feature = "encryption")]
        Some(key) => receive_file(
            config,
            local_path,
            remote_path,
            options,
            tftp_binary_common::keys::create_encryption_writer(key, create_writer),
            socket,
            instant_callback,
            OsRng,
        ),
        _ => receive_file(
            config,
            local_path,
            remote_path,
            options,
            create_writer,
            socket,
            instant_callback,
            OsRng,
        ),
    };
    let (total, remote_key) = result?;
    debug!("Client total received {total}");
    handle_hosts_file(args.known_hosts, remote_key, args.endpoint);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_endpoint() {
        let data = [
            ("127.0.0.1:9000", Some("127.0.0.1:9000")),
            ("127.0.0.1", Some("127.0.0.1:69")),
            ("[::1]:9000", Some("[::1]:9000")),
            ("::1", Some("[::1]:69")),
            ("::1:9000", Some("[::1]:9000")),
            ("2001:db8::1", Some("[2001:db8::1]:69")),
            ("localhost:9000", None),
        ];
        for (input, expected) in data {
            let expected = expected.map(|e| e.parse::<SocketAddr>().unwrap());
            assert_eq!(parse_endpoint(input).ok(), expected, "{input}");
        }
    }

    #[test]
    fn test_default_listen_matches_endpoint_family() {
        let v4 = default_listen("127.0.0.1:1".parse().unwrap());
        let v6 = default_listen("[::1]:1".parse().unwrap());
        assert!(v4.is_ipv4());
        assert!(v6.is_ipv6());
    }
}
