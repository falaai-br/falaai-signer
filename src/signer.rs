//! Emissão de `SenderCertificate`: valida a requisição do `accounts` e assina com a libsignal.

use libsignal_protocol::{Aci, DeviceId, IdentityKey, SenderCertificate, Timestamp};
use uuid::Uuid;

use crate::keys::SignerKeys;

/// Maior validade aceita para um certificado de remetente, a partir do instante da emissão. O
/// `accounts` usa 24h (ADR-0010); a folga só existe para não acoplar o serviço a esse número.
/// Validade no passado ou além disso indica unidade errada (segundos ou microssegundos).
pub const MAX_VALIDITY_MILLIS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Requisição recusada ou falha ao assinar. As mensagens não incluem os valores recebidos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// O ACI não tem 16 bytes.
    #[error("aci precisa ter 16 bytes")]
    InvalidAci,
    /// O device id está fora de 1..=127.
    #[error("device_id fora de 1..=127")]
    InvalidDeviceId,
    /// A chave de identidade não é uma chave pública da libsignal.
    #[error("identity_key inválida")]
    InvalidIdentityKey,
    /// A validade está no passado ou longe demais no futuro.
    #[error("expires_at fora da janela aceita")]
    InvalidExpiration,
    /// A libsignal falhou ao assinar.
    #[error("falha ao assinar o certificado")]
    Signing,
}

/// O que o `accounts` pede: o dispositivo e até quando o certificado vale.
#[derive(Clone, Copy)]
pub struct SenderCertificateRequest<'a> {
    /// ACI do remetente, 16 bytes do UUID.
    pub aci: &'a [u8],
    /// Device id do remetente.
    pub device_id: u32,
    /// Chave pública de identidade serializada pela libsignal (33 bytes).
    pub identity_key: &'a [u8],
    /// Validade em milissegundos desde a época Unix.
    pub expires_at_millis: u64,
}

/// Emissor de certificados de remetente. Sem estado além das chaves.
#[derive(Debug)]
pub struct Signer {
    keys: SignerKeys,
}

impl Signer {
    /// Emissor com as chaves já validadas.
    pub fn new(keys: SignerKeys) -> Self {
        Self { keys }
    }

    /// Trust root público serializado (33 bytes).
    pub fn trust_root(&self) -> Vec<u8> {
        self.keys.trust_root().serialize().to_vec()
    }

    /// Assina um `SenderCertificate` para o dispositivo de `request`, com o certificado do
    /// servidor embutido. `now_millis` é o instante da emissão, para conferir a validade.
    pub fn sign_sender_certificate(
        &self,
        request: &SenderCertificateRequest<'_>,
        now_millis: u64,
    ) -> Result<Vec<u8>, SignError> {
        let aci: [u8; 16] = request.aci.try_into().map_err(|_| SignError::InvalidAci)?;
        let aci = Aci::from(Uuid::from_bytes(aci));
        let device_id =
            DeviceId::try_from(request.device_id).map_err(|_| SignError::InvalidDeviceId)?;
        let identity_key =
            IdentityKey::decode(request.identity_key).map_err(|_| SignError::InvalidIdentityKey)?;
        let latest = now_millis.saturating_add(MAX_VALIDITY_MILLIS);
        if request.expires_at_millis <= now_millis || request.expires_at_millis > latest {
            return Err(SignError::InvalidExpiration);
        }

        let certificate = SenderCertificate::new(
            aci.service_id_string(),
            None,
            *identity_key.public_key(),
            device_id,
            Timestamp::from_epoch_millis(request.expires_at_millis),
            self.keys.server_certificate().clone(),
            self.keys.server_key(),
            &mut rand::rng(),
        )
        .map_err(|_| SignError::Signing)?;
        Ok(certificate
            .serialized()
            .map_err(|_| SignError::Signing)?
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::IdentityKeyPair;

    use super::*;
    use crate::keys;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const NOW: u64 = 1_767_225_600_000;
    const DAY: u64 = 24 * 60 * 60 * 1000;
    const ACI: [u8; 16] = [
        0x9d, 0x06, 0x52, 0xa3, 0xdc, 0xc3, 0x4d, 0x11, 0x97, 0x5f, 0x74, 0xd6, 0x15, 0x98, 0x73,
        0x3f,
    ];

    fn signer() -> Result<Signer, Box<dyn std::error::Error>> {
        let generated = keys::generate(1, &mut rand::rng())?;
        Ok(Signer::new(SignerKeys::from_json(
            &generated.signer_secret,
        )?))
    }

    fn identity() -> Vec<u8> {
        IdentityKeyPair::generate(&mut rand::rng())
            .identity_key()
            .serialize()
            .to_vec()
    }

    #[test]
    fn certificado_encadeia_ate_o_trust_root_com_os_campos_pedidos() -> TestResult {
        let signer = signer()?;
        let identity_key = identity();
        let request = SenderCertificateRequest {
            aci: &ACI,
            device_id: 3,
            identity_key: &identity_key,
            expires_at_millis: NOW + DAY,
        };
        let bytes = signer.sign_sender_certificate(&request, NOW)?;

        let certificate = SenderCertificate::deserialize(&bytes)?;
        let trust_root = libsignal_protocol::PublicKey::deserialize(&signer.trust_root())?;
        assert!(certificate.validate(&trust_root, Timestamp::from_epoch_millis(NOW))?);
        assert_eq!(
            certificate.sender_uuid()?,
            "9d0652a3-dcc3-4d11-975f-74d61598733f"
        );
        assert_eq!(certificate.sender_e164()?, None);
        assert_eq!(u32::from(certificate.sender_device_id()?), 3);
        assert_eq!(&*certificate.key()?.serialize(), &identity_key[..]);
        assert_eq!(certificate.expiration()?.epoch_millis(), NOW + DAY);
        assert_eq!(certificate.signer()?.key_id()?, 1);
        // Vencido depois da validade.
        let later = Timestamp::from_epoch_millis(NOW + DAY + 1);
        assert!(!certificate.validate(&trust_root, later)?);
        Ok(())
    }

    #[test]
    fn recusa_requisicoes_invalidas() -> TestResult {
        let signer = signer()?;
        let identity_key = identity();
        let valid = SenderCertificateRequest {
            aci: &ACI,
            device_id: 1,
            identity_key: &identity_key,
            expires_at_millis: NOW + DAY,
        };
        let cases = [
            (
                SenderCertificateRequest {
                    aci: &ACI[..15],
                    ..valid
                },
                SignError::InvalidAci,
            ),
            (
                SenderCertificateRequest { aci: &[], ..valid },
                SignError::InvalidAci,
            ),
            (
                SenderCertificateRequest {
                    device_id: 0,
                    ..valid
                },
                SignError::InvalidDeviceId,
            ),
            (
                SenderCertificateRequest {
                    device_id: 128,
                    ..valid
                },
                SignError::InvalidDeviceId,
            ),
            (
                SenderCertificateRequest {
                    identity_key: &identity_key[1..],
                    ..valid
                },
                SignError::InvalidIdentityKey,
            ),
            (
                SenderCertificateRequest {
                    identity_key: &[],
                    ..valid
                },
                SignError::InvalidIdentityKey,
            ),
            (
                SenderCertificateRequest {
                    expires_at_millis: NOW,
                    ..valid
                },
                SignError::InvalidExpiration,
            ),
            (
                // Segundos em vez de milissegundos: cai no passado.
                SenderCertificateRequest {
                    expires_at_millis: (NOW + DAY) / 1000,
                    ..valid
                },
                SignError::InvalidExpiration,
            ),
            (
                // Microssegundos: longe demais no futuro.
                SenderCertificateRequest {
                    expires_at_millis: (NOW + DAY) * 1000,
                    ..valid
                },
                SignError::InvalidExpiration,
            ),
            (
                SenderCertificateRequest {
                    expires_at_millis: NOW + MAX_VALIDITY_MILLIS + 1,
                    ..valid
                },
                SignError::InvalidExpiration,
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(signer.sign_sender_certificate(&request, NOW), Err(expected));
        }
        let longest = SenderCertificateRequest {
            expires_at_millis: NOW + MAX_VALIDITY_MILLIS,
            ..valid
        };
        assert!(signer.sign_sender_certificate(&longest, NOW).is_ok());
        Ok(())
    }

    #[test]
    fn device_ids_nos_limites() -> TestResult {
        let signer = signer()?;
        let identity_key = identity();
        for device_id in [1, 127] {
            let request = SenderCertificateRequest {
                aci: &ACI,
                device_id,
                identity_key: &identity_key,
                expires_at_millis: NOW + DAY,
            };
            let certificate =
                SenderCertificate::deserialize(&signer.sign_sender_certificate(&request, NOW)?)?;
            assert_eq!(u32::from(certificate.sender_device_id()?), device_id);
        }
        Ok(())
    }
}
