use core::fmt::Display;
use core::mem::size_of;
use core::ops::Deref;
use core::str::FromStr;

use base64::engine::GeneralPurpose;
use base64::Engine;
use chacha20poly1305::aead::Buffer;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::Key;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey as ExternalPublicKey;
use x25519_dalek::StaticSecret;

use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::MAX_EXTENSION_VALUE_SIZE;
use crate::error::EncodingErrorType;
use crate::error::EncryptionError;
use crate::packet::PacketType;
use crate::types::DataBuffer;
use crate::types::ShortString;

pub type PrivateKey = StaticSecret;
pub type PublicKey = ExternalPublicKey;
pub type Nonce = XNonce;

pub const ENCODED_PUBLIC_KEY_LENGTH: usize = ((4 * size_of::<PublicKey>() / 3) + 3) & !3;
pub const ENCODED_NONCE_LENGTH: usize = ((4 * size_of::<Nonce>() / 3) + 3) & !3;

const ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub type FinalizeKeysCallback = fn(&Option<PrivateKey>, &PublicKey) -> FinalizedKeys;

#[derive(Debug, Clone)]
pub enum EncryptionKeys {
    ClientKey(PublicKey),
    ServerKey(PublicKey, Nonce),
    // Local, Remote
    LocalToRemote(PublicKey, PublicKey),
}

pub enum InitialKey {
    Static(PrivateKey),
    Ephemeral(EphemeralSecret),
}

pub struct InitialKeys {
    pub public: PublicKey,
    pub private: InitialKey,
}

impl InitialKeys {
    pub fn new(public: PublicKey, private: InitialKey) -> Self {
        Self { public, private }
    }

    pub fn finalize(self, remote_public_key: &PublicKey, nonce: Nonce) -> FinalizedKeys {
        let key = match self.private {
            InitialKey::Static(k) => k.diffie_hellman(remote_public_key),
            InitialKey::Ephemeral(k) => k.diffie_hellman(remote_public_key),
        };
        let key: Key = key.to_bytes().into();
        FinalizedKeys {
            encryptor: Encryptor {
                cipher: XChaCha20Poly1305::new(&key),
                nonce,
            },
            public: self.public,
        }
    }
}

pub struct FinalizedKeys {
    pub encryptor: Encryptor,
    pub public: PublicKey,
}

impl FinalizedKeys {
    pub fn nonce(&self) -> &Nonce {
        &self.encryptor.nonce
    }
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

pub struct Encryptor {
    pub cipher: XChaCha20Poly1305,
    pub nonce: Nonce,
}

impl Encryptor {
    pub fn encrypt(&self, data: &mut dyn Buffer) -> Result<(), EncryptionError> {
        self.cipher
            .encrypt_in_place(&self.nonce, &[], data)
            .map_err(|_| EncryptionError::Decrypt)
    }

    pub fn decrypt(&self, data: &mut dyn Buffer) -> Result<(), EncryptionError> {
        self.cipher
            .decrypt_in_place(&self.nonce, &[], data)
            .map_err(|_| EncryptionError::Decrypt)
    }
}

pub fn encode_nonce(nonce: &Nonce) -> Result<ShortString, EncryptionError> {
    let mut public_bytes = [0; ENCODED_NONCE_LENGTH];
    ENGINE
        .encode_slice(nonce.deref(), &mut public_bytes)
        .map_err(|_| EncryptionError::Encode(EncodingErrorType::Nonce))?;
    Ok(public_bytes.into_iter().map(|b| b as char).collect())
}

pub fn encode_public_key(public: &PublicKey) -> Result<ShortString, EncryptionError> {
    let mut public_bytes = [0; ENCODED_PUBLIC_KEY_LENGTH];
    ENGINE
        .encode_slice(public.as_bytes(), &mut public_bytes)
        .map_err(|_| EncryptionError::Encode(EncodingErrorType::PublicKey))?;
    Ok(public_bytes.into_iter().map(|b| b as char).collect())
}

pub fn encode_private_key(private: &PrivateKey) -> Result<ShortString, EncryptionError> {
    let mut private_bytes = [0; ENCODED_PUBLIC_KEY_LENGTH];
    ENGINE
        .encode_slice(private.to_bytes(), &mut private_bytes)
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

pub fn overwrite_data_packet(
    buff: &mut DataBuffer,
    callback: impl Fn(&mut dyn Buffer) -> Result<(), EncryptionError>,
) -> Result<(), EncryptionError> {
    if let (Ok(PacketType::Data), Some(data_packet)) = (
        PacketType::from_bytes(buff),
        buff.get(DATA_PACKET_HEADER_SIZE as usize..),
    ) {
        #[allow(clippy::iter_cloned_collect)]
        let mut data: DataBuffer = data_packet.iter().copied().collect();
        callback(&mut data)?;
        buff.truncate(DATA_PACKET_HEADER_SIZE as usize);
        buff.extend(data);
    }
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
    use super::*;
    use crate::config::ENCRYPTION_TAG_SIZE;

    #[test]
    fn test_encrypt_decrypt() {
        let encryptor = create_encryptor();
        #[cfg(feature = "alloc")]
        let mut data = [2, 32, 32, 2, 1].to_vec();
        #[cfg(not(feature = "alloc"))]
        let mut data: DataBuffer = [2, 32, 32, 2, 1].into_iter().collect();
        let expected = data.clone();
        encryptor.encrypt(&mut data).unwrap();
        assert_ne!(data, expected);
        assert_eq!(data.len(), expected.len() + ENCRYPTION_TAG_SIZE as usize);
        encryptor.decrypt(&mut data).unwrap();
        assert_eq!(data, expected);
    }

    #[test]
    fn test_overwrite_data() {
        let encryptor = create_encryptor();
        #[cfg(feature = "alloc")]
        let mut data: alloc::vec::Vec<u8> = PacketType::Data
            .to_bytes()
            .into_iter()
            .chain([2, 32, 32, 2, 1, 11])
            .collect();
        #[cfg(not(feature = "alloc"))]
        let mut data: DataBuffer = PacketType::Data
            .to_bytes()
            .into_iter()
            .chain([2, 32, 32, 2, 1, 11].into_iter())
            .collect();
        let mut expected = data.clone();
        overwrite_data_packet(&mut data, |buf| encryptor.encrypt(buf)).unwrap();
        assert_ne!(data, expected);
        assert_eq!(data[..4], expected[..4]);
        assert_eq!(data.len(), expected.len() + ENCRYPTION_TAG_SIZE as usize);
        overwrite_data_packet(&mut data, |buf| encryptor.decrypt(buf)).unwrap();
        assert_eq!(data[..4], expected[..4]);
        assert_eq!(data, expected);

        data[0] = 255;
        expected[0] = 255;
        overwrite_data_packet(&mut data, |buf| encryptor.encrypt(buf)).unwrap();
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
        assert_eq!(encoded.len(), ENCODED_PUBLIC_KEY_LENGTH);
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
    fn test_encode_nonce() {
        let public: Nonce = [
            1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99,
        ]
        .into();
        let encoded = encode_nonce(&public).unwrap();
        assert_eq!(encoded.len(), ENCODED_NONCE_LENGTH);
        let decoded = decode_nonce(encoded.as_bytes()).unwrap();
        assert_eq!(public, decoded);
    }

    fn create_encryptor() -> Encryptor {
        Encryptor {
            cipher: XChaCha20Poly1305::new(
                &[
                    1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99,
                    233, 200, 17, 22, 29, 93, 32, 1,
                ]
                .into(),
            ),
            nonce: [
                1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99, 233, 200, 1, 3, 4, 5, 7, 3, 3, 3, 3, 2, 99,
            ]
            .into(),
        }
    }
}
