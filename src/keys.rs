//! Material de chave: o segredo que o serviço carrega e a geração de chaves de dev.
//!
//! O segredo do serviço é um JSON (arquivo em dev, Secrets Manager depois) com o trust root
//! público, o `ServerCertificate` assinado pelo trust root e a chave privada desse certificado,
//! em base64. A chave privada do trust root não entra no serviço: fica com quem gera o
//! certificado do servidor ([`generate`]).
//!
//! Os buffers com chave privada (arquivo lido, base64, bytes decodificados) são `Zeroizing`. A
//! `PrivateKey` da libsignal é `Copy` e não implementa `Zeroize`; a cópia que o serviço guarda
//! vive até o processo terminar e não há como apagá-la sem `unsafe`.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libsignal_protocol::{KeyPair, PrivateKey, PublicKey, ServerCertificate};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Falha ao ler ou gerar material de chave. As mensagens nunca incluem o conteúdo do segredo.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// O segredo não é um JSON com exatamente os campos esperados.
    #[error(
        "segredo malformado: esperado JSON com trust_root, server_certificate e server_private_key"
    )]
    Malformed,
    /// Um campo não está em base64.
    #[error("campo {0} não está em base64")]
    Encoding(&'static str),
    /// Um campo não é uma chave ou certificado válido da libsignal.
    #[error("campo {0} inválido")]
    Invalid(&'static str),
    /// O certificado do servidor não foi assinado pelo trust root, ou o id dele foi revogado.
    #[error("server_certificate não encadeia até o trust_root")]
    UntrustedServerCertificate,
    /// A chave privada não corresponde à chave pública do certificado do servidor.
    #[error("server_private_key não corresponde ao server_certificate")]
    KeyMismatch,
    /// Erro da libsignal ao gerar ou assinar.
    #[error("libsignal: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),
}

/// O segredo do serviço, como está no JSON.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecretDocument {
    trust_root: String,
    server_certificate: String,
    server_private_key: Zeroizing<String>,
}

/// Par do trust root, como sai de [`generate`]. Fica fora do serviço.
#[derive(Serialize)]
struct TrustRootDocument {
    public_key: String,
    private_key: Zeroizing<String>,
}

/// Chaves do serviço, já validadas: o certificado do servidor encadeia até o trust root e a
/// chave privada é a dele.
pub struct SignerKeys {
    trust_root: PublicKey,
    server_certificate: ServerCertificate,
    server_key: PrivateKey,
}

impl SignerKeys {
    /// Lê e valida o segredo do serviço (JSON).
    pub fn from_json(secret: &[u8]) -> Result<Self, KeyError> {
        let document: SecretDocument =
            serde_json::from_slice(secret).map_err(|_| KeyError::Malformed)?;
        let trust_root = decode("trust_root", &document.trust_root)?;
        let trust_root =
            PublicKey::deserialize(&trust_root).map_err(|_| KeyError::Invalid("trust_root"))?;
        let server_certificate = decode("server_certificate", &document.server_certificate)?;
        let server_certificate = ServerCertificate::deserialize(&server_certificate)
            .map_err(|_| KeyError::Invalid("server_certificate"))?;
        let server_key = decode("server_private_key", &document.server_private_key)?;
        let server_key = PrivateKey::deserialize(&server_key)
            .map_err(|_| KeyError::Invalid("server_private_key"))?;
        Self::new(trust_root, server_certificate, server_key)
    }

    fn new(
        trust_root: PublicKey,
        server_certificate: ServerCertificate,
        server_key: PrivateKey,
    ) -> Result<Self, KeyError> {
        if !server_certificate.validate(&trust_root)? {
            return Err(KeyError::UntrustedServerCertificate);
        }
        let derived = server_key
            .public_key()
            .map_err(|_| KeyError::Invalid("server_private_key"))?;
        if derived != server_certificate.public_key()? {
            return Err(KeyError::KeyMismatch);
        }
        Ok(Self {
            trust_root,
            server_certificate,
            server_key,
        })
    }

    /// Trust root público.
    pub fn trust_root(&self) -> &PublicKey {
        &self.trust_root
    }

    /// Certificado do servidor, embutido em todo certificado de remetente.
    pub fn server_certificate(&self) -> &ServerCertificate {
        &self.server_certificate
    }

    /// Chave privada do certificado do servidor.
    pub(crate) fn server_key(&self) -> &PrivateKey {
        &self.server_key
    }
}

impl fmt::Debug for SignerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerKeys")
            .field("trust_root", &self.trust_root)
            .field("server_key", &"<omitida>")
            .finish_non_exhaustive()
    }
}

/// Saída de [`generate`]: os dois documentos JSON, com chave privada, prontos para gravar.
pub struct GeneratedKeys {
    /// Par do trust root. Guardar fora do serviço; o público vai na build do app.
    pub trust_root: Zeroizing<Vec<u8>>,
    /// Segredo do serviço, no formato de [`SignerKeys::from_json`].
    pub signer_secret: Zeroizing<Vec<u8>>,
    /// Trust root público serializado (33 bytes).
    pub trust_root_public: Vec<u8>,
}

/// Gera um trust root e uma chave de servidor novos e assina o `ServerCertificate` de id
/// `key_id`. Uso em dev; o par do trust root de produção é gerado e guardado fora do repositório.
pub fn generate<R: Rng + CryptoRng>(key_id: u32, rng: &mut R) -> Result<GeneratedKeys, KeyError> {
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let server_certificate =
        ServerCertificate::new(key_id, server_key.public_key, &trust_root.private_key, rng)?;
    // Recusa, por exemplo, um id revogado pela libsignal.
    let keys = SignerKeys::new(
        trust_root.public_key,
        server_certificate,
        server_key.private_key,
    )?;

    let trust_root_document = TrustRootDocument {
        public_key: STANDARD.encode(trust_root.public_key.serialize()),
        private_key: encode_private(&trust_root.private_key),
    };
    let secret_document = SecretDocument {
        trust_root: STANDARD.encode(keys.trust_root.serialize()),
        server_certificate: STANDARD.encode(keys.server_certificate.serialized()?),
        server_private_key: encode_private(&keys.server_key),
    };
    Ok(GeneratedKeys {
        trust_root: to_json(&trust_root_document)?,
        signer_secret: to_json(&secret_document)?,
        trust_root_public: trust_root.public_key.serialize().to_vec(),
    })
}

fn decode(field: &'static str, value: &str) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    STANDARD
        .decode(value)
        .map(Zeroizing::new)
        .map_err(|_| KeyError::Encoding(field))
}

fn encode_private(key: &PrivateKey) -> Zeroizing<String> {
    let bytes = Zeroizing::new(key.serialize());
    Zeroizing::new(STANDARD.encode(bytes.as_slice()))
}

fn to_json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let mut json =
        Zeroizing::new(serde_json::to_vec_pretty(value).map_err(|_| KeyError::Malformed)?);
    json.push(b'\n');
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn secret_value(json: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(json)
    }

    #[test]
    fn segredo_gerado_carrega_e_encadeia_ate_o_trust_root() -> TestResult {
        let generated = generate(7, &mut rand::rng())?;
        let keys = SignerKeys::from_json(&generated.signer_secret)?;
        assert_eq!(
            &*keys.trust_root().serialize(),
            generated.trust_root_public.as_slice()
        );
        assert_eq!(keys.server_certificate().key_id()?, 7);
        assert!(keys.server_certificate().validate(keys.trust_root())?);
        Ok(())
    }

    #[test]
    fn par_do_trust_root_corresponde_ao_publico() -> TestResult {
        let generated = generate(1, &mut rand::rng())?;
        let document = secret_value(&generated.trust_root)?;
        let private = STANDARD.decode(document["private_key"].as_str().unwrap_or_default())?;
        let public = PrivateKey::deserialize(&private)?.public_key()?;
        assert_eq!(&*public.serialize(), generated.trust_root_public.as_slice());
        Ok(())
    }

    #[test]
    fn recusa_certificado_de_outro_trust_root() -> TestResult {
        let ours = generate(1, &mut rand::rng())?;
        let other = generate(1, &mut rand::rng())?;
        let mut document = secret_value(&ours.signer_secret)?;
        document["trust_root"] = secret_value(&other.signer_secret)?["trust_root"].clone();
        let result = SignerKeys::from_json(&serde_json::to_vec(&document)?);
        assert!(matches!(result, Err(KeyError::UntrustedServerCertificate)));
        Ok(())
    }

    #[test]
    fn recusa_chave_privada_de_outro_certificado() -> TestResult {
        let ours = generate(1, &mut rand::rng())?;
        let other = generate(1, &mut rand::rng())?;
        let mut document = secret_value(&ours.signer_secret)?;
        document["server_private_key"] =
            secret_value(&other.signer_secret)?["server_private_key"].clone();
        let result = SignerKeys::from_json(&serde_json::to_vec(&document)?);
        assert!(matches!(result, Err(KeyError::KeyMismatch)));
        Ok(())
    }

    #[test]
    fn recusa_id_revogado_pela_libsignal() {
        assert!(matches!(
            generate(0xDEAD_C357, &mut rand::rng()),
            Err(KeyError::UntrustedServerCertificate)
        ));
    }

    #[test]
    fn recusa_segredo_malformado() -> TestResult {
        let generated = generate(1, &mut rand::rng())?;
        let mut extra = secret_value(&generated.signer_secret)?;
        extra["trust_root_private_key"] = "x".into();
        let mut not_base64 = secret_value(&generated.signer_secret)?;
        not_base64["server_private_key"] = "não é base64".into();
        let mut short_key = secret_value(&generated.signer_secret)?;
        short_key["server_private_key"] = STANDARD.encode([1u8; 31]).into();

        assert!(matches!(
            SignerKeys::from_json(b"{}"),
            Err(KeyError::Malformed)
        ));
        assert!(matches!(
            SignerKeys::from_json(b"nada"),
            Err(KeyError::Malformed)
        ));
        assert!(matches!(
            SignerKeys::from_json(&serde_json::to_vec(&extra)?),
            Err(KeyError::Malformed)
        ));
        assert!(matches!(
            SignerKeys::from_json(&serde_json::to_vec(&not_base64)?),
            Err(KeyError::Encoding("server_private_key"))
        ));
        assert!(matches!(
            SignerKeys::from_json(&serde_json::to_vec(&short_key)?),
            Err(KeyError::Invalid("server_private_key"))
        ));
        Ok(())
    }

    #[test]
    fn debug_omite_a_chave_privada() -> TestResult {
        let generated = generate(1, &mut rand::rng())?;
        let keys = SignerKeys::from_json(&generated.signer_secret)?;
        let private = secret_value(&generated.signer_secret)?["server_private_key"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let debug = format!("{keys:?}");
        assert!(debug.contains("<omitida>"));
        assert!(!debug.contains(&private));
        Ok(())
    }
}
