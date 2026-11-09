#[cfg(feature = "encryption")]
pub use implementation::*;

#[cfg(feature = "encryption")]
mod implementation {
    use std::fs::File as StdFile;

    use log::warn;
    use rand::CryptoRng;
    use rand::RngCore;
    use tftp_dus::encryption::decode_signing_key;
    use tftp_dus::encryption::decode_verifying_key;
    use tftp_dus::encryption::EncryptionKey;
    use tftp_dus::encryption::SigningKey;
    use tftp_dus::encryption::StreamEncryptor;
    use tftp_dus::encryption::VerifyingKey;
    use tftp_dus::encryption::STREAM_NONCE_SIZE;
    use tftp_dus::error::BoxedResult;
    use tftp_dus::error::EncryptionError;
    use tftp_dus::key_management::append_to_known_hosts;
    use tftp_dus::key_management::get_from_known_hosts;
    use tftp_dus::key_management::read_authorized_keys;
    use tftp_dus::key_management::AuthorizedKeys;
    use tftp_dus::readers::encrypted_stream_reader::encrypted_stream_size;
    use tftp_dus::readers::encrypted_stream_reader::StreamReader;
    use tftp_dus::std_compat::io::BufRead;
    use tftp_dus::std_compat::io::Read;
    use tftp_dus::std_compat::io::Seek;
    use tftp_dus::std_compat::io::Write;
    use tftp_dus::types::FilePath;
    use tftp_dus::writers::encrypted_stream_writer::StreamWriter;

    use crate::io::create_line_reader;
    use crate::io::from_io_err;
    use crate::io::File;

    pub fn create_encryption_writer<CreateWriter, W>(
        key: EncryptionKey,
        create_writer: CreateWriter,
    ) -> impl FnOnce(&FilePath) -> BoxedResult<StreamWriter<W>>
    where
        W: Write,
        CreateWriter: FnOnce(&FilePath) -> BoxedResult<W>,
    {
        move |path| Ok(StreamWriter::new(create_writer(path)?, key))
    }

    /// `block_size` is the size blocks are expected to be read in. The reported
    /// size is exact as long as the server does not negotiate a different one.
    pub fn create_encryption_reader<CreateReader, R>(
        key: EncryptionKey,
        mut rng: impl CryptoRng + RngCore,
        block_size: u16,
        create_reader: CreateReader,
    ) -> impl FnOnce(&FilePath) -> BoxedResult<(Option<u64>, StreamReader<R>)>
    where
        R: Read + Seek,
        CreateReader: FnOnce(&FilePath) -> BoxedResult<(Option<u64>, R)>,
    {
        let mut nonce = [0_u8; STREAM_NONCE_SIZE as usize];
        rng.fill_bytes(&mut nonce);
        let encryptor = StreamEncryptor::new(&key, &nonce);
        move |path: &FilePath| {
            let (file_size, r) = create_reader(path)?;
            // a pipe also reports 0, which says nothing about how much it will produce
            let stream_size = file_size
                .filter(|size| *size > 0)
                .and_then(|size| encrypted_stream_size(size, block_size));
            Ok((stream_size, StreamReader::new(encryptor, r, nonce)))
        }
    }

    pub fn read_private_value_or_file(private: &str) -> Result<SigningKey, EncryptionError> {
        let result = decode_signing_key(private.as_bytes());
        if result.is_err() {
            if let Ok(reader) = create_line_reader(private) {
                if let Some(Ok(line)) = reader.lines().next() {
                    if let Ok(key) = decode_signing_key(line.trim_end().as_bytes()) {
                        return Ok(key);
                    }
                }
            }
        }
        result
    }

    pub fn load_private_key(value: Option<&str>) -> BoxedResult<Option<SigningKey>> {
        Ok(value.map(read_private_value_or_file).transpose()?)
    }

    pub fn load_encryption_key(value: Option<&str>) -> BoxedResult<Option<EncryptionKey>> {
        Ok(value
            .map(read_private_value_or_file)
            .transpose()?
            .map(|key| key.to_bytes()))
    }

    pub fn load_remote_public_key(
        server_public_key: Option<&str>,
        known_hosts: Option<&str>,
        endpoint: &str,
    ) -> BoxedResult<Option<VerifyingKey>> {
        Ok(match (server_public_key, known_hosts) {
            (Some(key), _) => Some(decode_verifying_key(key.as_bytes())?),
            (_, Some(path)) => get_from_known_hosts(create_line_reader(path)?, endpoint)?,
            _ => None,
        })
    }

    pub fn load_authorized_keys(path: Option<&str>) -> BoxedResult<Option<AuthorizedKeys>> {
        path.map(|path| read_authorized_keys(create_line_reader(path)?))
            .transpose()
    }

    pub fn handle_hosts_file(
        known_hosts_file: Option<&str>,
        remote_key: Option<VerifyingKey>,
        endpoint: &str,
    ) {
        let Some((path, key)) = known_hosts_file.zip(remote_key) else {
            return;
        };
        if let Ok(reader) = create_line_reader(path) {
            if let Ok(Some(_)) = get_from_known_hosts(reader, endpoint) {
                return;
            }
        }
        // File is a separate wrapper type without std
        #[allow(clippy::useless_conversion)]
        let result: BoxedResult<()> = StdFile::options()
            .create(true)
            .append(true)
            .open(path)
            .map_err(from_io_err)
            .map_err(Into::into)
            .and_then(|file| append_to_known_hosts(File::from(file), endpoint, &key));
        if let Err(e) = result {
            warn!("Failed to append to known hosts {e}");
        }
    }
}

#[cfg(not(feature = "encryption"))]
pub use no_encryption::*;

/// Same functions as `implementation`, for builds that have no keys to load.
#[cfg(not(feature = "encryption"))]
mod no_encryption {
    use tftp_dus::encryption::EncryptionKey;
    use tftp_dus::encryption::SigningKey;
    use tftp_dus::encryption::VerifyingKey;
    use tftp_dus::error::BoxedResult;
    use tftp_dus::key_management::AuthorizedKeys;

    pub fn load_private_key(_value: Option<&str>) -> BoxedResult<Option<SigningKey>> {
        Ok(None)
    }

    pub fn load_encryption_key(_value: Option<&str>) -> BoxedResult<Option<EncryptionKey>> {
        Ok(None)
    }

    pub fn load_remote_public_key(
        _server_public_key: Option<&str>,
        _known_hosts: Option<&str>,
        _endpoint: &str,
    ) -> BoxedResult<Option<VerifyingKey>> {
        Ok(None)
    }

    pub fn load_authorized_keys(_path: Option<&str>) -> BoxedResult<Option<AuthorizedKeys>> {
        Ok(None)
    }

    pub fn handle_hosts_file(
        _known_hosts_file: Option<&str>,
        _remote_key: Option<VerifyingKey>,
        _endpoint: &str,
    ) {
    }
}

#[cfg(all(test, feature = "encryption"))]
mod tests {
    use tftp_dus::encryption::VerifyingKey;
    use tftp_dus::key_management::get_from_known_hosts;

    use super::*;
    use crate::io::create_line_reader;

    const PRIVATE_KEY: &str = "XnXn2SAxtXlUAXlobJsCW9BRg6XKNcKCS4XNoaMjJJk=";

    fn sample_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tftp-keys-{}-{name}", std::process::id()))
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encryption_reader_reports_size_of_the_stream() {
        use std::io::Cursor;

        use tftp_dus::readers::encrypted_stream_reader::encrypted_stream_size;
        use tftp_dus::types::FilePath;

        let path: FilePath = "file".parse().unwrap();
        let size_for = |file_size| {
            let create_reader = move |_: &FilePath| Ok((file_size, Cursor::new(vec![0_u8; 8])));
            let create = create_encryption_reader([1; 32], rand::rngs::OsRng, 512, create_reader);
            create(&path).unwrap().0
        };

        assert_eq!(size_for(Some(5000)), encrypted_stream_size(5000, 512));
        assert_eq!(size_for(Some(0)), None);
        assert_eq!(size_for(None), None);
    }

    #[test]
    fn test_read_private_value_from_argument_and_file() {
        let path = sample_path("private");
        std::fs::write(&path, format!("{PRIVATE_KEY}\n")).unwrap();
        let from_file = read_private_value_or_file(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        let from_value = read_private_value_or_file(PRIVATE_KEY).unwrap();
        assert_eq!(from_file.to_bytes(), from_value.to_bytes());
        assert!(read_private_value_or_file("/nonexistent/key.pem").is_err());
    }

    #[test]
    fn test_handle_hosts_file_appends_once() {
        let path = sample_path("known");
        let _ = std::fs::remove_file(&path);
        let key = VerifyingKey::from(&read_private_value_or_file(PRIVATE_KEY).unwrap());
        handle_hosts_file(path.to_str(), Some(key), "server");
        handle_hosts_file(path.to_str(), Some(key), "server");
        let contents = std::fs::read_to_string(&path).unwrap();
        let reader = create_line_reader(path.to_str().unwrap()).unwrap();
        let found = get_from_known_hosts(reader, "server").unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(contents.matches("server").count(), 1);
        assert_eq!(found, Some(key));
    }
}
