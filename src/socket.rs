use core::time::Duration;

use crate::{
    config::ConnectionOptions,
    encryption::{overwrite_data_packet, EncryptionKeys, EncryptionLevel, Encryptor, PublicKey},
    std_compat::{
        io::{Error, ErrorKind, Result},
        net::SocketAddr,
    },
    types::DataBuffer,
};

pub trait Socket {
    fn recv_from(
        &self,
        buf: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> Result<(usize, SocketAddr)>;
    fn send_to(&self, buf: &mut DataBuffer, addr: SocketAddr) -> Result<usize>;
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;
    fn local_addr(&self) -> Result<SocketAddr>;
}

#[cfg(feature = "encryption")]
pub struct EncryptionBoundSocket<S> {
    pub socket: S,
    pub encryptor: Option<Encryptor>,
    pub encryption_level: EncryptionLevel,
    pub public_key: Option<PublicKey>,
}

#[cfg(feature = "encryption")]
impl<S> EncryptionBoundSocket<S> {
    pub fn new(
        socket: S,
        encryptor: Option<Encryptor>,
        public_key: PublicKey,
        encryption_level: EncryptionLevel,
    ) -> Self {
        Self {
            socket,
            encryptor,
            encryption_level,
            public_key: public_key.into(),
        }
    }

    pub fn wrap(socket: S) -> Self {
        Self {
            socket,
            encryptor: None,
            encryption_level: EncryptionLevel::None,
            public_key: None,
        }
    }
}

#[cfg(feature = "encryption")]
impl<S> Socket for EncryptionBoundSocket<S>
where
    S: Socket,
{
    fn recv_from(
        &self,
        buff: &mut DataBuffer,
        wait_for: Option<Duration>,
    ) -> Result<(usize, SocketAddr)> {
        let (received_length, s) = self.socket.recv_from(buff, wait_for)?;
        buff.truncate(received_length);
        log::trace!("Received data {:x?}", buff);
        match (self.encryption_level, &self.encryptor) {
            (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) => {
                encryptor
                    .decrypt(buff)
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
            }
            (EncryptionLevel::Data, Some(encryptor)) => {
                overwrite_data_packet(buff, |buff| encryptor.decrypt(buff))
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
            }
            _ => (),
        }
        Ok((buff.len(), s))
    }

    fn send_to(&self, buff: &mut DataBuffer, endpoint: SocketAddr) -> Result<usize> {
        use crate::packet::PacketType;
        log::trace!("Send data {:x?}", buff);
        match (self.encryption_level, &self.encryptor) {
            (EncryptionLevel::Protocol | EncryptionLevel::Full, Some(encryptor)) => {
                let packet_type = PacketType::from_bytes(buff);
                encryptor
                    .encrypt(buff)
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
                // encrypt initial packet
                if let Ok(PacketType::Read | PacketType::Write) = packet_type {
                    *buff = PacketType::InitialEncryption
                        .to_bytes()
                        .into_iter()
                        .chain(self.public_key.unwrap().as_bytes().iter().copied())
                        .chain(encryptor.nonce.into_iter())
                        .chain(buff.iter().copied())
                        .collect();
                }
            }
            (EncryptionLevel::Data, Some(encryptor)) => {
                overwrite_data_packet(buff, |buff| encryptor.encrypt(buff))
                    .map_err(|_| Error::from(ErrorKind::InvalidData))?;
            }
            _ => (),
        }
        self.socket.send_to(buff, endpoint)
    }

    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }
}
