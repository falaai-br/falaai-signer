//! Onde o serviço escuta: socket Unix ou TCP em loopback. Nada além disso é aceito, porque só o
//! `accounts`, no mesmo pod, pode chamar o signer (ADR-0011).

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Prefixo de um endereço de socket Unix: `unix:/caminho/do.sock`.
const UNIX_PREFIX: &str = "unix:";

/// Endereço de escuta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenAddr {
    /// TCP em endereço de loopback (`127.0.0.0/8` ou `::1`).
    Tcp(SocketAddr),
    /// Socket Unix no caminho dado.
    Unix(PathBuf),
}

/// Endereço de escuta recusado.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListenAddrError {
    /// Não é `unix:<caminho>` nem `ip:porta`.
    #[error("endereço de escuta inválido: use unix:/caminho.sock ou 127.0.0.1:porta")]
    Malformed,
    /// TCP fora do loopback.
    #[error("o signer só escuta em loopback ou socket Unix")]
    NotLoopback,
}

impl FromStr for ListenAddr {
    type Err = ListenAddrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(path) = value.strip_prefix(UNIX_PREFIX) {
            if path.is_empty() {
                return Err(ListenAddrError::Malformed);
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        let address: SocketAddr = value.parse().map_err(|_| ListenAddrError::Malformed)?;
        if !address.ip().is_loopback() {
            return Err(ListenAddrError::NotLoopback);
        }
        Ok(Self::Tcp(address))
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(address) => write!(f, "{address}"),
            Self::Unix(path) => write!(f, "{UNIX_PREFIX}{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aceita_loopback_e_socket_unix() {
        for (value, expected) in [
            (
                "127.0.0.1:50051",
                ListenAddr::Tcp(([127, 0, 0, 1], 50051).into()),
            ),
            ("127.0.0.2:1", ListenAddr::Tcp(([127, 0, 0, 2], 1).into())),
            (
                "[::1]:50051",
                ListenAddr::Tcp(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 50051))),
            ),
            (
                "unix:/run/falaai/signer.sock",
                ListenAddr::Unix("/run/falaai/signer.sock".into()),
            ),
        ] {
            assert_eq!(value.parse(), Ok(expected.clone()), "{value}");
            assert_eq!(expected.to_string(), value);
        }
    }

    #[test]
    fn recusa_fora_do_loopback() {
        for value in [
            "0.0.0.0:50051",
            "[::]:50051",
            "10.0.0.5:50051",
            "192.168.0.1:1",
        ] {
            assert_eq!(
                value.parse::<ListenAddr>(),
                Err(ListenAddrError::NotLoopback),
                "{value}"
            );
        }
    }

    #[test]
    fn recusa_malformado() {
        for value in [
            "",
            "unix:",
            "localhost:50051",
            "127.0.0.1",
            "tcp://127.0.0.1:1",
        ] {
            assert_eq!(
                value.parse::<ListenAddr>(),
                Err(ListenAddrError::Malformed),
                "{value}"
            );
        }
    }
}
