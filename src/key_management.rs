use chacha20poly1305::{AeadCore, XChaCha20Poly1305};
use rand::{CryptoRng, RngCore};
use x25519_dalek::EphemeralSecret;

use crate::{
    config::MAX_EXTENSION_VALUE_SIZE,
    encryption::{
        decode_private_key, decode_public_key, encode_public_key, EncryptionKeys, FinalizedKeys,
        InitialKey, InitialKeys, Nonce, PrivateKey, PublicKey,
    },
    error::{BoxedError, BoxedResult, EncryptionError},
    server::AuthorizedKeys,
    std_compat::io::{BufRead, Write},
    types::{DefaultString, ExtensionValue},
};

pub fn create_initial_keys(
    private: &Option<PrivateKey>,
    mut rng: impl CryptoRng + RngCore,
) -> InitialKeys {
    match private {
        Some(k) => InitialKeys {
            public: PublicKey::from(k),
            private: InitialKey::Static(k.clone()),
        },
        None => {
            let random_key = EphemeralSecret::new(&mut rng);
            InitialKeys {
                public: PublicKey::from(&random_key),
                private: InitialKey::Ephemeral(random_key),
            }
        }
    }
}

pub fn create_finalized_keys(
    private: &Option<PrivateKey>,
    remote_public_key: &PublicKey,
    nonce: Option<Nonce>,
    mut rng: impl CryptoRng + RngCore + Copy,
) -> FinalizedKeys {
    let initial_keys = create_initial_keys(private, rng);
    initial_keys.finalize(
        remote_public_key,
        nonce.unwrap_or_else(|| XChaCha20Poly1305::generate_nonce(rng)),
    )
}

#[allow(unused_must_use)]
pub fn read_authorized_keys(reader: impl BufRead) -> BoxedResult<AuthorizedKeys> {
    let mut authorized_keys = AuthorizedKeys::new();
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let key = decode_public_key(line.as_bytes())?;
        authorized_keys.push(key);
    }
    Ok::<_, BoxedError>(authorized_keys)
}

pub fn get_from_known_hosts(
    reader: impl BufRead,
    endpoint: &str,
) -> BoxedResult<Option<PublicKey>> {
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        match line.split_once(' ') {
            Some((remote_endpoint, encoded_key)) if remote_endpoint == endpoint => {
                return Ok(decode_public_key(encoded_key.as_bytes())?.into())
            }
            _ => continue,
        }
    }
    Ok(None)
}

pub fn append_to_known_hosts(
    mut file: impl Write,
    endpoint: &str,
    public_key: &PublicKey,
) -> BoxedResult<()> {
    file.write_fmt(format_args!(
        "\n{} {}\n",
        endpoint,
        encode_public_key(public_key)?
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use vfs::{MemoryFS, VfsPath};

    use super::*;

    #[test]
    fn test_read_authorized_keys() {
        let root: VfsPath = MemoryFS::new().into();
        let path = root.join("keys").unwrap();
        path
            .create_file()
            .unwrap()
            .write_all(b"\n#Hello world\nDRKEZZt4qRdz7gp14XNyvGsFT95Fo/oFj5A+b35s8TI=\n/RtKjvdVy3lnPjPwTyXNvMsWBIFjfaG3kvOQ3VOMItg=")
            .unwrap();
        let keys = read_authorized_keys(create_buff_reader(path.open_file().unwrap())).unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_read_authorized_keys_error() {
        let root: VfsPath = MemoryFS::new().into();
        let path = root.join("keys").unwrap();
        path
            .create_file()
            .unwrap()
            .write_all(b"\nHello world\nDRKEZZt4qRdz7gp14XNyvGsFT95Fo/oFj5A+b35s8TI=\n/RtKjvdVy3lnPjPwTyXNvMsWBIFjfaG3kvOQ3VOMItg=")
            .unwrap();
        let keys = read_authorized_keys(create_buff_reader(path.open_file().unwrap()));
        assert!(keys.is_err());
    }

    #[test]
    fn test_append_to_known_hosts() {
        let root: VfsPath = MemoryFS::new().into();
        let path = root.join("keys").unwrap();
        path
            .create_file()
            .unwrap()
            .write_all(b"\n#Hello world\nserver DRKEZZt4qRdz7gp14XNyvGsFT95Fo/oFj5A+b35s8TI=\na b /RtKjvdVy3lnPjPwTyXNvMsWBIFjfaG3kvOQ3VOMItg=")
            .unwrap();
        let key =
            get_from_known_hosts(create_buff_reader(path.open_file().unwrap()), "server").unwrap();
        let expected =
            decode_public_key("DRKEZZt4qRdz7gp14XNyvGsFT95Fo/oFj5A+b35s8TI=".as_bytes()).unwrap();
        assert_eq!(Some(expected), key);

        let file = path.append_file().unwrap();
        #[cfg(not(feature = "std"))]
        let file = StdCompatFile(file);
        append_to_known_hosts(file, "new-server", &expected).unwrap();

        let key = get_from_known_hosts(create_buff_reader(path.open_file().unwrap()), "new-server")
            .unwrap();

        assert_eq!(Some(expected), key);

        let key = get_from_known_hosts(create_buff_reader(path.open_file().unwrap()), "a");
        assert!(key.is_err());
    }

    pub fn create_buff_reader<T: std::io::Read>(reader: T) -> StdBufReader<T> {
        let file = std::io::BufReader::new(reader);
        #[cfg(all(not(feature = "std"), feature = "encryption"))]
        let file = StdBufReader(file);
        file
    }

    #[cfg(not(feature = "std"))]
    pub struct StdCompatFile(pub std::boxed::Box<dyn std::io::Write + Send>);

    #[cfg(not(feature = "std"))]
    impl crate::std_compat::io::Write for StdCompatFile {
        fn write(&mut self, buf: &[u8]) -> crate::std_compat::io::Result<usize> {
            use std::io::Write;
            self.0.write(buf).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::InvalidData)
            })
        }

        fn write_fmt(
            &mut self,
            fmt: core::fmt::Arguments<'_>,
        ) -> crate::std_compat::io::Result<()> {
            use std::io::Write;
            self.0.write_fmt(fmt).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::InvalidData)
            })
        }

        fn flush(&mut self) -> crate::std_compat::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(all(feature = "std", feature = "encryption"))]
    pub type StdBufReader<T> = std::io::BufReader<T>;
    #[cfg(all(not(feature = "std"), feature = "encryption"))]
    pub struct StdBufReader<T: std::io::Read>(std::io::BufReader<T>);
    #[cfg(all(not(feature = "std"), feature = "encryption"))]
    impl<T: std::io::Read> crate::std_compat::io::BufRead for StdBufReader<T> {
        fn read_line(
            &mut self,
            buf: &mut crate::types::DefaultString,
        ) -> crate::std_compat::io::Result<usize> {
            use std::io::BufRead;
            let mut s = std::string::String::new();
            let result = self.0.read_line(&mut s).map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::InvalidData)
            });
            let _result = buf.push_str(s.as_str());
            #[cfg(not(feature = "alloc"))]
            _result.map_err(|_| {
                crate::std_compat::io::Error::from(crate::std_compat::io::ErrorKind::InvalidData)
            })?;
            result
        }
    }
}
