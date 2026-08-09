use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ShadowsocksNode {
    cipher: ShadowsocksCipher,
    credential: ShadowsocksCredential,
}

impl ShadowsocksNode {
    pub(crate) fn new(
        cipher: ShadowsocksCipher,
        credential: ShadowsocksCredential,
    ) -> Option<Self> {
        let node = Self { cipher, credential };
        let valid = match (node.cipher().credential_requirement(), node.credential()) {
            (
                ShadowsocksCredentialRequirement::Password,
                ShadowsocksCredential::Password(password),
            ) => password.byte_len() > 0,
            (
                ShadowsocksCredentialRequirement::Psk { byte_len },
                ShadowsocksCredential::Psk(psk),
            ) => psk.byte_len() == byte_len,
            _ => false,
        };
        valid.then_some(node)
    }

    pub(crate) const fn cipher(&self) -> &ShadowsocksCipher {
        &self.cipher
    }

    pub(crate) const fn credential(&self) -> &ShadowsocksCredential {
        &self.credential
    }
}

impl fmt::Debug for ShadowsocksNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShadowsocksNode")
            .field("cipher", self.cipher())
            .field("credential", self.credential())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShadowsocksCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
}

impl ShadowsocksCipher {
    pub(crate) const fn credential_requirement(&self) -> ShadowsocksCredentialRequirement {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::Chacha20IetfPoly1305 => {
                ShadowsocksCredentialRequirement::Password
            }
            Self::Blake3Aes128Gcm => ShadowsocksCredentialRequirement::Psk { byte_len: 16 },
            Self::Blake3Aes256Gcm => ShadowsocksCredentialRequirement::Psk { byte_len: 32 },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShadowsocksCredentialRequirement {
    Password,
    Psk { byte_len: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShadowsocksCredential {
    Password(SecretString),
    Psk(SecretBytes),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretString(String);

impl SecretString {
    pub(crate) fn new(value: String) -> Option<Self> {
        (!value.is_empty()).then_some(Self(value))
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn new(value: Vec<u8>) -> Option<Self> {
        matches!(value.len(), 16 | 32).then_some(Self(value))
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}
