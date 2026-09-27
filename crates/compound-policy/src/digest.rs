use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{fmt, str::FromStr};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_ref());
        Self(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_placeholder(&self) -> bool {
        self.0 == "sha256:REPLACE_WITH_PINNED_DIGEST"
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.0
    }
}

impl TryFrom<String> for Digest {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Digest::from_str(&value)
    }
}

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "sha256:REPLACE_WITH_PINNED_DIGEST" {
            return Ok(Self(value.to_owned()));
        }

        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(DigestError::UnsupportedAlgorithm(value.to_owned()));
        };

        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DigestError::InvalidSha256(value.to_owned()));
        }

        Ok(Self(format!("sha256:{}", hex.to_ascii_lowercase())))
    }
}

#[derive(Debug, Error)]
pub enum DigestError {
    #[error("digest must use sha256: prefix: {0}")]
    UnsupportedAlgorithm(String),
    #[error("sha256 digest must contain 64 hex characters: {0}")]
    InvalidSha256(String),
}
