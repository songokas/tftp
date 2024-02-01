use core::fmt::Display;
use core::mem::size_of;
use core::str::FromStr;

use base64::engine::GeneralPurpose;
use base64::Engine;
use chacha20poly1305::aead::stream::DecryptorBE32;
use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::aead::Buffer;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::AeadCore;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::Key;
use chacha20poly1305::Tag;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use rand::CryptoRng;
use rand::RngCore;
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey as ExternalPublicKey;
use x25519_dalek::StaticSecret;

use crate::buffer::extend_from_slice;
use crate::buffer::SliceExt;
use crate::config::ENCRYPTION_NONCE_SIZE;
use crate::config::ENCRYPTION_PADDING_SIZE;
use crate::config::MAX_EXTENSION_VALUE_SIZE;
use crate::error::EncodingErrorType;
use crate::error::EncryptionError;
use crate::error::PaddingError;
use crate::types::DataBuffer;
use crate::types::ShortString;

pub type EncryptionKey = [u8; ENCRYPTION_KEY_SIZE as usize];
pub type PrivateKey = StaticSecret;
pub type PublicKey = ExternalPublicKey;
pub type Nonce = XNonce;
pub type StreamNonce = [u8; STREAM_NONCE_SIZE as usize];

pub const STREAM_NONCE_SIZE: u8 = 19;
pub const ENCRYPTION_KEY_SIZE: u8 = size_of::<PrivateKey>() as u8;
pub const PUBLIC_KEY_SIZE: u8 = size_of::<PublicKey>() as u8;
pub const STREAM_BLOCK_SIZE: u8 = 2;

pub const ENCODED_PUBLIC_KEY_LENGTH: u8 = ((4 * PUBLIC_KEY_SIZE / 3) + 3) & !3;
pub const ENCODED_NONCE_LENGTH: u8 = ((4 * ENCRYPTION_NONCE_SIZE / 3) + 3) & !3;

const ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub type FinalizeKeysCallback<Rng> = fn(&Option<PrivateKey>, &PublicKey) -> FinalizedKeys<Rng>;

#[derive(Debug, Clone)]
pub enum EncryptionKeys {
    ClientKey(PublicKey),
    ServerKey(PublicKey),
    // Local, Remote
    LocalToRemote(PublicKey, PublicKey),
}

pub enum InitialKey {
    Static(PrivateKey),
    Ephemeral(EphemeralSecret),
}

pub struct InitialKeyPair {
    pub public: PublicKey,
    pub private: InitialKey,
}

impl InitialKeyPair {
    pub fn new(public: PublicKey, private: InitialKey) -> Self {
        Self { public, private }
    }

    pub fn finalize<R>(self, remote_public_key: &PublicKey, rng: R) -> FinalizedKeys<R> {
        let key = match self.private {
            InitialKey::Static(k) => k.diffie_hellman(remote_public_key),
            InitialKey::Ephemeral(k) => k.diffie_hellman(remote_public_key),
        };

        let key: Key = key.to_bytes().into();
        FinalizedKeys {
            encryptor: Encryptor {
                cipher: XChaCha20Poly1305::new(&key),
                rng,
            },
            public: self.public,
        }
    }
}

pub struct FinalizedKeys<Rng> {
    pub encryptor: Encryptor<Rng>,
    pub public: PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionLevel {
    Data,
    Protocol,
    Full,
    OptionalData,
    OptionalProtocol,
    None,
}

impl FromStr for EncryptionLevel {
    type Err = EncryptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "data" => Self::Data,
            "protocol" => Self::Protocol,
            "full" => Self::Full,
            "optional-data" => Self::OptionalData,
            "optional-protocol" => Self::OptionalProtocol,
            "none" => Self::None,
            _ => return Err(EncryptionError::Encrypt),
        })
    }
}

impl Display for EncryptionLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncryptionLevel::Data => write!(f, "data"),
            EncryptionLevel::Protocol => write!(f, "protocol"),
            EncryptionLevel::Full => write!(f, "full"),
            EncryptionLevel::OptionalData => write!(f, "optional-data"),
            EncryptionLevel::OptionalProtocol => write!(f, "optional-protocol"),
            EncryptionLevel::None => write!(f, "none"),
        }
    }
}

pub struct StreamEncryptor {
    pub stream_encryptor: Option<EncryptorBE32<XChaCha20Poly1305>>,
}

impl StreamEncryptor {
    pub fn new(key: &EncryptionKey, nonce: &StreamNonce) -> StreamEncryptor {
        let aead = XChaCha20Poly1305::new(key.into());
        let stream_encryptor = EncryptorBE32::from_aead(aead, nonce.into());
        StreamEncryptor {
            stream_encryptor: stream_encryptor.into(),
        }
    }
}

impl StreamEncryptor {
    pub fn encrypt(
        &mut self,
        data: &mut dyn Buffer,
        block_size: usize,
    ) -> Result<(), EncryptionError> {
        if block_size == data.len() {
            self.stream_encryptor
                .as_mut()
                .ok_or(EncryptionError::NoStream)?
                .encrypt_next_in_place(&[], data)
                .map_err(|_| EncryptionError::Encrypt)
        } else {
            self.stream_encryptor
                .take()
                .ok_or(EncryptionError::NoStream)?
                .encrypt_last_in_place(&[], data)
                .map_err(|_| EncryptionError::Encrypt)
        }
    }
}

pub struct StreamDecryptor {
    pub stream_decryptor: Option<DecryptorBE32<XChaCha20Poly1305>>,
}

impl StreamDecryptor {
    pub fn new(key: &EncryptionKey, nonce: &StreamNonce) -> StreamDecryptor {
        let aead = XChaCha20Poly1305::new(key.into());
        let stream_decryptor = DecryptorBE32::from_aead(aead, nonce.into());
        StreamDecryptor {
            stream_decryptor: stream_decryptor.into(),
        }
    }
}

impl StreamDecryptor {
    pub fn decrypt(
        &mut self,
        data: &mut dyn Buffer,
        block_size: usize,
    ) -> Result<(), EncryptionError> {
        if block_size == data.len() {
            self.stream_decryptor
                .as_mut()
                .ok_or(EncryptionError::NoStream)?
                .decrypt_next_in_place(&[], data)
                .map_err(|_| EncryptionError::Decrypt)
        } else {
            self.stream_decryptor
                .take()
                .ok_or(EncryptionError::NoStream)?
                .decrypt_last_in_place(&[], data)
                .map_err(|_| EncryptionError::Decrypt)
        }
    }
}

// always encrypt with random nonce
// expects nonce at the end for decryption
pub struct Encryptor<R> {
    pub cipher: XChaCha20Poly1305,
    pub rng: R,
}

impl<R: CryptoRng + RngCore + Clone> Encryptor<R> {
    pub fn encrypt(
        &self,
        buffer: &mut DataBuffer,
        from_position: usize,
    ) -> Result<(), EncryptionError> {
        let nonce = XChaCha20Poly1305::generate_nonce(self.rng.clone());
        let (_, data) = buffer.split_at_mut(from_position);

        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, &[], data)
            .map_err(|_| EncryptionError::Encrypt)?;
        extend_from_slice(buffer, &tag, EncryptionError::Tag)?;
        extend_from_slice(buffer, &nonce, EncryptionError::Nonce)?;
        Ok(())
    }

    pub fn decrypt(
        &self,
        buffer: &mut DataBuffer,
        from_position: usize,
    ) -> Result<(), EncryptionError> {
        let nonce: Nonce = buffer
            .as_slice()
            .rslice_to_array(0_usize)
            .ok_or(EncryptionError::Decrypt)?
            .into();
        let tag: Tag = buffer
            .as_slice()
            .rslice_to_array(nonce.len())
            .ok_or(EncryptionError::Decrypt)?
            .into();
        buffer.truncate(buffer.len() - nonce.len() - tag.len());
        let (_, data) = buffer.split_at_mut(from_position);
        self.cipher
            .decrypt_in_place_detached(&nonce, &[], data, &tag)
            .map_err(|_| EncryptionError::Decrypt)
    }
}

pub fn encode_public_key(public: &PublicKey) -> Result<ShortString, EncryptionError> {
    let mut public_bytes = [0; ENCODED_PUBLIC_KEY_LENGTH as usize];
    ENGINE
        .encode_slice(public.as_bytes(), &mut public_bytes)
        .map_err(|_| EncryptionError::Encode(EncodingErrorType::PublicKey))?;
    Ok(public_bytes.into_iter().map(|b| b as char).collect())
}

pub fn encode_private_key(private: &PrivateKey) -> Result<ShortString, EncryptionError> {
    let mut private_bytes = [0; ENCODED_PUBLIC_KEY_LENGTH as usize];
    ENGINE
        .encode_slice(private, &mut private_bytes)
        .map_err(|_| EncryptionError::Encode(EncodingErrorType::PrivateKey))?;
    Ok(private_bytes.into_iter().map(|b| b as char).collect())
}

pub fn decode_private_key(data: &[u8]) -> Result<PrivateKey, EncryptionError> {
    decode(data, EncodingErrorType::PrivateKey)
}

pub fn decode_nonce(data: &[u8]) -> Result<Nonce, EncryptionError> {
    decode(data, EncodingErrorType::Nonce)
}

pub fn decode_public_key(data: &[u8]) -> Result<PublicKey, EncryptionError> {
    decode(data, EncodingErrorType::PublicKey)
}

// 0010 0200 | 1111 1111 1111 1111
// 0010 0201 | 0000 0000 0000 0000
pub fn apply_bit_padding(buf: &mut DataBuffer, expected_size: usize) -> Result<(), PaddingError> {
    let Some(last_byte) = buf.last() else {
        return Err(PaddingError::EmptyBuffer);
    };
    // lets pad with 0
    let number_of_bytes = expected_size
        .checked_sub(buf.len())
        .ok_or(PaddingError::InvalidSizeProvided)?;
    let ones = last_byte.trailing_ones();
    let byte = if ones > 0 { 0 } else { 255 };
    for _ in 0..number_of_bytes + ENCRYPTION_PADDING_SIZE as usize {
        #[cfg(feature = "alloc")]
        buf.push(byte);
        #[cfg(not(feature = "alloc"))]
        buf.push(byte)
            .map_err(|_| PaddingError::InvalidSizeProvided)?;
    }
    Ok(())
}

// last byte must me a padding byte
pub fn remove_bit_padding(buf: &mut DataBuffer) -> Result<(), PaddingError> {
    let Some(last_byte) = buf.last() else {
        return Err(PaddingError::EmptyBuffer);
    };
    let byte: u8 = if last_byte.trailing_ones() == 8 {
        255
    } else if last_byte.trailing_zeros() == 8 {
        0
    } else {
        return Err(PaddingError::MissingPaddingByte);
    };
    let mut number_of_bytes = 0;
    for b in buf.iter().rev() {
        if *b != byte {
            break;
        }
        number_of_bytes += 1;
    }
    buf.truncate(buf.len() - number_of_bytes);
    Ok(())
}

fn decode<Output: From<[u8; CAP]>, const CAP: usize>(
    data: &[u8],
    error_type: EncodingErrorType,
) -> Result<Output, EncryptionError> {
    let mut remote = [0; { MAX_EXTENSION_VALUE_SIZE as usize }];
    ENGINE
        .decode_slice(data, &mut remote)
        .map_err(|_| EncryptionError::Decode(error_type))?;
    if remote[CAP] != 0 {
        return Err(EncryptionError::Decode(error_type));
    }
    let remote: [u8; CAP] = remote[..CAP]
        .try_into()
        .map_err(|_| EncryptionError::Decode(error_type))?;
    Ok(remote.into())
}

#[cfg(test)]
mod tests {
    use rand::rngs::ThreadRng;

    use super::*;
    use crate::config::ENCRYPTION_TAG_SIZE;

    #[test]
    fn test_apply_bit_padding() {
        let mut buf = DataBuffer::new();
        let result = apply_bit_padding(&mut buf, 5);
        assert!(result.is_err());
        assert_eq!(buf, []);

        buf.extend([255]);
        apply_bit_padding(&mut buf, 5).unwrap();
        assert_eq!(buf, [255, 0, 0, 0, 0, 0]);

        let mut buf = DataBuffer::new();
        // buf.resize(10, 0);
        buf.extend([0]);
        apply_bit_padding(&mut buf, 5).unwrap();
        assert_eq!(buf, [0, 255, 255, 255, 255, 255]);

        let mut buf = DataBuffer::new();
        buf.extend([0]);
        apply_bit_padding(&mut buf, 1).unwrap();
        assert_eq!(buf, [0, 255]);

        let mut buf = DataBuffer::new();
        buf.extend([0, 1, 2, 3, 0]);
        let result = apply_bit_padding(&mut buf, 0);
        assert!(result.is_err());

        let mut buf = DataBuffer::new();
        buf.extend([0, 1, 2, 3, 0]);
        let result = apply_bit_padding(&mut buf, 2000);
        #[cfg(feature = "alloc")]
        assert!(result.is_ok());
        #[cfg(not(feature = "alloc"))]
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_bit_padding() {
        let mut buf = DataBuffer::new();
        let result = remove_bit_padding(&mut buf);
        assert!(result.is_err());
        assert_eq!(buf, []);

        buf.extend([2, 0, 0, 0, 0]);
        remove_bit_padding(&mut buf).unwrap();
        assert_eq!(buf, [2]);

        let mut buf = DataBuffer::new();
        // buf.resize(10, 0);
        buf.extend([1, 255, 255, 255, 255]);
        remove_bit_padding(&mut buf).unwrap();
        assert_eq!(buf, [1]);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let encryptor = create_encryptor();
        #[cfg(feature = "alloc")]
        let mut data = [2, 32, 32, 2, 1].to_vec();
        #[cfg(not(feature = "alloc"))]
        let mut data: DataBuffer = [2, 32, 32, 2, 1].into_iter().collect();
        let expected = data.clone();
        encryptor.encrypt(&mut data, 0).unwrap();
        assert_ne!(data, expected);
        assert_eq!(
            data.len(),
            expected.len() + ENCRYPTION_TAG_SIZE as usize + ENCRYPTION_NONCE_SIZE as usize
        );
        encryptor.decrypt(&mut data, 0).unwrap();
        assert_eq!(data, expected);
    }

    #[test]
    fn test_encode_public_key() {
        let public: PublicKey = [
            1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200,
            17, 22, 29, 93, 32, 1,
        ]
        .into();
        let encoded = encode_public_key(&public).unwrap();
        assert_eq!(encoded.len(), ENCODED_PUBLIC_KEY_LENGTH as usize);
        let decoded = decode_public_key(encoded.as_bytes()).unwrap();
        assert_eq!(public, decoded);
    }

    #[test]
    fn test_decode_public_key() {
        let data = [
            (true, "4vF5bMfogaX8gd4U6mlefIaZYmJlUK7zrl9Z20iQa88="),
            (true, "qTuwoxbFqBB96g=="),
            (false, "amigo%"),
            (false, "0IYTomuQrvWzX0VG8Ak2JS7FkXCuUOd2y3ehCQxWqc+7"),
        ];
        for (expected, public) in data {
            let encoded = decode_public_key(public.as_bytes());
            assert_eq!(expected, encoded.is_ok(), "{public}");
        }
    }

    #[test]
    fn test_decode_nonce() {
        let data = [
            (true, "tgcjcdnaLMP6HgCy0VxQE4HGJI+nVhPT"),
            (true, "qTuwoxbFqBB96g=="),
            (false, "4vF5bMfogaX8gd4U6mlefIaZYmJlUK7zrl9Z20iQa88="),
            (false, "amigo%"),
        ];
        for (expected, nonce) in data {
            let encoded = decode_nonce(nonce.as_bytes());
            assert_eq!(expected, encoded.is_ok(), "{nonce}");
        }
    }

    #[test]
    fn test_encrypt_decrypt_stream() {
        let mut encryptor = create_stream_encryptor();
        let mut decryptor = create_stream_decryptor();
        for bytes in [[2, 32], [32, 2], [1, 0]] {
            #[cfg(feature = "alloc")]
            let mut data = bytes.to_vec();
            #[cfg(not(feature = "alloc"))]
            let mut data: crate::types::DataBlock07 = bytes.into_iter().collect();
            // data.truncate(2);
            let expected = data.clone();
            encryptor.encrypt(&mut data, 2).unwrap();
            assert_ne!(data, expected);
            assert_eq!(data.len(), expected.len() + ENCRYPTION_TAG_SIZE as usize);
            decryptor.decrypt(&mut data, 18).unwrap();
            assert_eq!(data, expected);
        }
    }

    fn create_encryptor() -> Encryptor<ThreadRng> {
        Encryptor {
            cipher: XChaCha20Poly1305::new(
                &[
                    1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99,
                    233, 200, 17, 22, 29, 93, 32, 1,
                ]
                .into(),
            ),
            rng: rand::thread_rng(),
        }
    }

    fn create_stream_encryptor() -> StreamEncryptor {
        StreamEncryptor::new(
            &[
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ]
            .into(),
            &[1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3].into(),
        )
    }

    fn create_stream_decryptor() -> StreamDecryptor {
        StreamDecryptor::new(
            &[
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233,
                200, 17, 22, 29, 93, 32, 1,
            ]
            .into(),
            &[1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3].into(),
        )
    }
}
