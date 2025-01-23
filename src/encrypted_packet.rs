use rand::CryptoRng;
use rand::RngCore;

use crate::buffer::extend_from_slice;
use crate::buffer::SliceExt;
use crate::config::DATA_PACKET_HEADER_SIZE;
use crate::config::ENCRYPTION_NONCE_SIZE;
use crate::config::ENCRYPTION_PADDING_SIZE;
use crate::config::ENCRYPTION_TAG_SIZE;
use crate::encryption::apply_bit_padding;
use crate::encryption::remove_bit_padding;
use crate::encryption::Encryptor;
use crate::encryption::Nonce;
use crate::encryption::PublicKey;
use crate::encryption::PUBLIC_KEY_SIZE;
use crate::error::EncryptedPacketError;
use crate::packet::PacketType;
use crate::types::DataBuffer;
use crate::types::PacketBlock;

#[allow(unused)]
pub struct PaddedPacketBlock<'a> {
    data: &'a PacketBlock,
    padding: &'a [u8],
    padding_byte: u8,
}

pub type Tag<'a> = &'a [u8; ENCRYPTION_TAG_SIZE as usize];

#[allow(unused)]
pub struct CipherText<'a> {
    data: &'a [u8],
    tag: Tag<'a>,
    buffer: &'a [u8],
}

impl<'a> CipherText<'a> {
    pub fn from_bytes(buffer: &'a [u8]) -> Result<Self, EncryptedPacketError> {
        let tag = buffer
            .rslice_to_array_ref(0_usize)
            .ok_or(EncryptedPacketError::Tag)?;

        Ok(Self {
            data: buffer
                .slice_at_end(tag.len())
                .ok_or(EncryptedPacketError::CipherText)?,
            tag,
            buffer,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }
}

#[allow(unused)]
pub struct InitialPacket<'a> {
    pub cipher_text: CipherText<'a>,
    pub nonce: &'a Nonce,
    pub public_key: PublicKey,
}

impl<'a> InitialPacket<'a> {
    pub fn from_bytes(buffer: &'a [u8]) -> Result<Self, EncryptedPacketError> {
        let public_key: PublicKey = buffer
            .rslice_to_array(0_usize)
            .ok_or(EncryptedPacketError::PublicKey)?
            .into();
        let nonce: &Nonce = buffer
            .rslice_to_array_ref(public_key.as_bytes().len())
            .ok_or(EncryptedPacketError::Nonce)?
            .into();
        let cipher_text = CipherText::from_bytes(
            buffer
                .slice_at_end(public_key.as_bytes().len() + nonce.len())
                .ok_or(EncryptedPacketError::CipherText)?,
        )?;
        Ok(Self {
            cipher_text,
            nonce,
            public_key,
        })
    }

    pub fn encrypt<Rng: CryptoRng + RngCore + Clone>(
        encryptor: &Encryptor<Rng>,
        buffer: &'a mut DataBuffer,
        expected_block_size: u16,
        public_key: &PublicKey,
    ) -> Result<(), EncryptedPacketError> {
        const RESERVED: u8 =
            ENCRYPTION_PADDING_SIZE + ENCRYPTION_TAG_SIZE + PUBLIC_KEY_SIZE + ENCRYPTION_NONCE_SIZE;
        let block_size = expected_block_size
            .checked_sub(RESERVED as u16)
            .ok_or(EncryptedPacketError::InvalidData)?;
        apply_bit_padding(buffer, block_size as usize)?;
        encryptor.encrypt(buffer, 0)?;
        extend_from_slice(
            buffer,
            public_key.as_bytes(),
            EncryptedPacketError::PublicKey,
        )?;
        Ok(())
    }

    pub fn decrypt<Rng: CryptoRng + RngCore + Clone>(
        self,
        encryptor: &Encryptor<Rng>,
    ) -> Result<DataBuffer, EncryptedPacketError> {
        // TODO allocation
        let mut buffer = DataBuffer::new();
        extend_from_slice(
            &mut buffer,
            self.cipher_text.as_bytes(),
            EncryptedPacketError::InvalidData,
        )?;
        extend_from_slice(&mut buffer, self.nonce, EncryptedPacketError::Nonce)?;
        encryptor.decrypt(&mut buffer, 0)?;
        remove_bit_padding(&mut buffer)?;
        Ok(buffer)
    }
}

#[allow(unused)]
pub struct EncryptedDataPacket<'a> {
    packet_type: PacketType,
    block: u16,
    cipher_text: CipherText<'a>,
    nonce: &'a Nonce,
}

impl<'a> EncryptedDataPacket<'a> {
    pub fn encrypt<Rng: CryptoRng + RngCore + Clone>(
        encryptor: &Encryptor<Rng>,
        buffer: &'a mut DataBuffer,
    ) -> Result<(), EncryptedPacketError> {
        encryptor.encrypt(buffer, DATA_PACKET_HEADER_SIZE as usize)?;
        Ok(())
    }

    pub fn decrypt<Rng: CryptoRng + RngCore + Clone>(
        encryptor: &Encryptor<Rng>,
        buffer: &mut DataBuffer,
    ) -> Result<(), EncryptedPacketError> {
        encryptor.decrypt(buffer, DATA_PACKET_HEADER_SIZE as usize)?;
        Ok(())
    }
}

#[allow(unused)]
pub struct EncryptedPacket<'a> {
    cipher_text: &'a CipherText<'a>,
    nonce: &'a Nonce,
}

impl<'a> EncryptedPacket<'a> {
    pub fn encrypt<Rng: CryptoRng + RngCore + Clone>(
        encryptor: &Encryptor<Rng>,
        buffer: &'a mut DataBuffer,
        expected_block_size: u16,
    ) -> Result<(), EncryptedPacketError> {
        apply_bit_padding(buffer, expected_block_size as usize)?;
        encryptor.encrypt(buffer, 0)?;
        Ok(())
    }

    pub fn decrypt<Rng: CryptoRng + RngCore + Clone>(
        encryptor: &Encryptor<Rng>,
        buffer: &mut DataBuffer,
    ) -> Result<(), EncryptedPacketError> {
        encryptor.decrypt(buffer, 0)?;
        remove_bit_padding(buffer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_from_bytes() {
        let cipher_text = [1, 1, 1, 1, 1, 1, 1];
        let tag = [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];
        let nonce = [
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ];
        let public_key = [
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2,
        ];
        let mut buffer: DataBuffer = cipher_text.into_iter().collect();
        buffer.extend(tag);
        buffer.extend(nonce);
        buffer.extend(public_key);
        let packet = InitialPacket::from_bytes(&buffer).unwrap();
        assert_eq!(packet.public_key, public_key.into());
        assert_eq!(packet.nonce.as_slice(), &nonce);
        assert_eq!(packet.cipher_text.tag, &tag);
        assert_eq!(packet.cipher_text.data, cipher_text);
        let data = packet.cipher_text.as_bytes();
        let expected: DataBuffer = cipher_text.into_iter().chain(tag).collect();
        assert_eq!(data, expected);
    }
}
