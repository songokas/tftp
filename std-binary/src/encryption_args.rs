//! Everything the binary knows about encryption options. Builds without the
//! `encryption` feature have the same types, with no flags and no values.

#[cfg(not(feature = "encryption"))]
pub use disabled::*;
#[cfg(feature = "encryption")]
pub use enabled::*;
use tftp_dus::types::FilePath;

/// The client's encryption options, whichever build this is.
pub struct ClientEncryptionValues<'a> {
    pub level: &'a str,
    pub private_key: Option<&'a str>,
    pub server_public_key: Option<&'a str>,
    pub known_hosts: Option<&'a FilePath>,
    pub encryption_key: Option<&'a str>,
}

/// The server's encryption options, whichever build this is.
#[derive(Default)]
pub struct ServerEncryptionValues<'a> {
    pub authorized_keys: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub require_full_encryption: Option<bool>,
    pub error_to_authorized_only: Option<bool>,
}

#[cfg(feature = "encryption")]
mod enabled {
    use core::str::FromStr;

    use clap::Args;
    use clap::ValueHint;
    use tftp_dus::types::ShortString;

    use super::*;

    fn try_from_str<T: FromStr>(arg: &str) -> Result<T, &'static str> {
        T::from_str(arg).map_err(|_| "Failed to parse")
    }

    #[derive(Args, Debug, Clone)]
    pub struct ClientEncryptionArgs {
        #[arg(
            long,
            default_value = "optional-protocol",
            help = "Available values protocol, data, optional-data, optional-protocol, none",
            value_parser = try_from_str::<ShortString>,
        )]
        pub encryption_level: ShortString,

        #[arg(long, help = "Base64 encoded private key to use: value or FILE", value_parser = try_from_str::<ShortString>)]
        pub private_key: Option<ShortString>,

        #[arg(
            long,
            help = "Base64 encoded remote server public key to use for encryption",
            value_parser = try_from_str::<ShortString>,
        )]
        pub server_public_key: Option<ShortString>,

        #[arg(
            long,
            help = "Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line",
            value_hint = ValueHint::FilePath,
            value_parser = try_from_str::<FilePath>,
        )]
        pub known_hosts: Option<FilePath>,

        #[arg(
            long,
            help = "Encrypt/decrypt file when sending/receiving. Key should be 32 chars long",
            value_parser = try_from_str::<ShortString>,
        )]
        pub encryption_key: Option<ShortString>,
    }

    impl ClientEncryptionArgs {
        pub fn values(&self) -> ClientEncryptionValues<'_> {
            ClientEncryptionValues {
                level: self.encryption_level.as_str(),
                private_key: self.private_key.as_deref(),
                server_public_key: self.server_public_key.as_deref(),
                known_hosts: self.known_hosts.as_ref(),
                encryption_key: self.encryption_key.as_deref(),
            }
        }
    }

    #[derive(Args, Debug, Clone)]
    pub struct ServerEncryptionArgs {
        #[arg(
            long,
            help = "Path to a file with authorized public keys. Each line contains base64(public key)",
            value_parser = try_from_str::<FilePath>,
            value_hint = ValueHint::FilePath,
        )]
        pub authorized_keys: Option<FilePath>,

        #[arg(long, help = "Base64 encoded private key to use: value or FILE", value_parser = try_from_str::<ShortString>)]
        pub private_key: Option<ShortString>,

        #[arg(
            long,
            help = "Require that connections be fully encrypted. This is enabled if authorized keys are provided",
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        pub require_full_encryption: Option<bool>,

        #[arg(
            long,
            help = "Provide connection errors to authorized clients only. Enabled by default when require-full-encryption=true",
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        pub error_to_authorized_only: Option<bool>,
    }

    impl ServerEncryptionArgs {
        pub fn values(&self) -> ServerEncryptionValues<'_> {
            ServerEncryptionValues {
                authorized_keys: self.authorized_keys.as_deref(),
                private_key: self.private_key.as_deref(),
                require_full_encryption: self.require_full_encryption,
                error_to_authorized_only: self.error_to_authorized_only,
            }
        }
    }

    #[cfg(test)]
    pub mod test_support {
        use tftp_dus::encryption::*;
        use tftp_dus::types::ShortString;

        use super::ClientEncryptionArgs;

        pub fn client_args(
            level: EncryptionLevel,
            server_public_key: Option<ShortString>,
            private_key: Option<ShortString>,
        ) -> ClientEncryptionArgs {
            ClientEncryptionArgs {
                encryption_level: level.to_string().parse().unwrap(),
                private_key,
                server_public_key,
                known_hosts: None,
                encryption_key: None,
            }
        }

        pub fn encoded_public_key(key: Option<&SigningKey>) -> Option<ShortString> {
            key.map(|k| encode_verifying_key(&VerifyingKey::from(k)).unwrap())
        }

        pub fn encoded_private_key(key: Option<&SigningKey>) -> Option<ShortString> {
            key.map(|k| encode_signing_key(k).unwrap())
        }
    }
}

#[cfg(not(feature = "encryption"))]
mod disabled {
    use clap::Args;

    use super::*;

    #[derive(Args, Debug, Clone)]
    pub struct ClientEncryptionArgs {}

    impl ClientEncryptionArgs {
        pub fn values(&self) -> ClientEncryptionValues<'_> {
            ClientEncryptionValues {
                level: "none",
                private_key: None,
                server_public_key: None,
                known_hosts: None,
                encryption_key: None,
            }
        }
    }

    #[derive(Args, Debug, Clone)]
    pub struct ServerEncryptionArgs {}

    impl ServerEncryptionArgs {
        pub fn values(&self) -> ServerEncryptionValues<'_> {
            ServerEncryptionValues::default()
        }
    }

    #[cfg(test)]
    pub mod test_support {
        use tftp_dus::encryption::*;
        use tftp_dus::types::ShortString;

        use super::ClientEncryptionArgs;

        pub fn client_args(
            _level: EncryptionLevel,
            _server_public_key: Option<ShortString>,
            _private_key: Option<ShortString>,
        ) -> ClientEncryptionArgs {
            ClientEncryptionArgs {}
        }

        pub fn encoded_public_key(_key: Option<&SigningKey>) -> Option<ShortString> {
            None
        }

        pub fn encoded_private_key(_key: Option<&SigningKey>) -> Option<ShortString> {
            None
        }
    }
}
