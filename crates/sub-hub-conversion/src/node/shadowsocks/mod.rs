use std::fmt;

mod share;
pub(crate) use share::parse;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ShadowsocksNode {
    cipher: ShadowsocksCipher,
    credential: ShadowsocksCredential,
    obfs: Option<ShadowsocksObfs>,
}

impl ShadowsocksNode {
    pub(crate) fn new(
        cipher: ShadowsocksCipher,
        credential: ShadowsocksCredential,
        obfs: Option<ShadowsocksObfs>,
    ) -> Option<Self> {
        let node = Self {
            cipher,
            credential,
            obfs,
        };
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

    pub(crate) const fn obfs(&self) -> Option<&ShadowsocksObfs> {
        self.obfs.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShadowsocksObfs {
    mode: ShadowsocksObfsMode,
    host: Option<String>,
}

impl ShadowsocksObfs {
    pub(crate) fn new(mode: ShadowsocksObfsMode, host: Option<String>) -> Option<Self> {
        let host_ok = host.as_ref().is_none_or(|value| !value.is_empty());
        host_ok.then_some(Self { mode, host })
    }

    pub(crate) const fn mode(&self) -> ShadowsocksObfsMode {
        self.mode
    }

    pub(crate) fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShadowsocksObfsMode {
    Http,
    Tls,
}

impl ShadowsocksObfsMode {
    pub(crate) const fn as_token(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tls => "tls",
        }
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

    pub(crate) fn expose(&self) -> &str {
        &self.0
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

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}
