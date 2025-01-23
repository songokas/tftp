use std::fs::File as StdFile;

use log::warn;
use rand::CryptoRng;
use rand::RngCore;
use tftp_dus::encryption::decode_private_key;
use tftp_dus::encryption::EncryptionKey;
use tftp_dus::encryption::PrivateKey;
use tftp_dus::encryption::PublicKey;
use tftp_dus::encryption::StreamEncryptor;
use tftp_dus::encryption::STREAM_NONCE_SIZE;
use tftp_dus::error::BoxedResult;
use tftp_dus::error::EncryptionError;
use tftp_dus::key_management::append_to_known_hosts;
use tftp_dus::key_management::get_from_known_hosts;
use tftp_dus::readers::encrypted_stream_reader::StreamReader;
use tftp_dus::std_compat::io::Read;
use tftp_dus::std_compat::io::Seek;
use tftp_dus::std_compat::io::Write;
use tftp_dus::types::FilePath;
use tftp_dus::writers::encrypted_stream_writer::StreamWriter;

use crate::io::create_buff_reader;
use crate::std_compat::fs::File;
use crate::std_compat::io::from_io_err;

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

pub fn create_encryption_reader<CreateReader, R>(
    key: EncryptionKey,
    mut rng: impl CryptoRng + RngCore,
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
        // TODO file size adjusted for the block size
        let (_, r) = create_reader(path)?;
        Ok((None, StreamReader::new(encryptor, r, nonce)))
    }
}

pub fn read_private_value_or_file(private: &str) -> Result<PrivateKey, EncryptionError> {
    #[cfg(feature = "std")]
    use std::io::BufRead;

    #[cfg(not(feature = "std"))]
    use tftp_dus::std_compat::io::BufRead;

    let result = decode_private_key(private.as_bytes());

    if result.is_err() {
        if let Ok(mut reader) = create_buff_reader(private) {
            #[cfg(not(feature = "std"))]
            let mut buf = tftp_dus::types::DefaultString::new();
            #[cfg(feature = "std")]
            let mut buf = String::new();
            if reader.read_line(&mut buf).is_ok() {
                if let Ok(p) = decode_private_key(buf.trim_end().as_bytes()) {
                    return Ok(p);
                }
            }
        }
    }
    result
}

pub fn handle_hosts_file(
    known_hosts_file: Option<&str>,
    remote_key: Option<PublicKey>,
    endpoint: &str,
) {
    match known_hosts_file
        .zip(remote_key)
        .map(|(f, k)| {
            if let Ok(r) = create_buff_reader(f) {
                if let Ok(Some(_)) = get_from_known_hosts(r, endpoint) {
                    return Ok(());
                }
            };

            let file: File = StdFile::options()
                .create(true)
                .append(true)
                .open(f)
                .map_err(from_io_err)?
                .into();
            append_to_known_hosts(file, endpoint, &k)
        })
        .transpose()
    {
        Ok(_) => (),
        Err(e) => warn!("Failed to append to known hosts {}", e),
    };
}
