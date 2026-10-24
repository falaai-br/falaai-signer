//! Vetores de certificado de remetente compartilhados com o falaai-core.
//!
//! `testdata/vectors/sender_certificate.json` tem um trust root público, a identidade de um
//! remetente de teste e um `SenderCertificate` emitido pelo signer para ela, com validade fixa.
//! O teste confere que o certificado versionado abre um sealed sender por `sealed_sender_decrypt`
//! na libsignal do commit pinado (o mesmo do falaai-core), e que o gerador ainda produz o mesmo
//! formato. O falaai-core pode ler o mesmo arquivo para validar do lado dele.
//!
//! As assinaturas são aleatórias, então o arquivo só muda quando regerado de propósito, com
//! `make vectors`.

mod common;

use std::error::Error;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{PLAINTEXT, TestResult, open_sealed};
use falaai_signer::keys::{self, SignerKeys};
use falaai_signer::signer::{SenderCertificateRequest, Signer};
use libsignal_protocol::{IdentityKeyPair, PublicKey, SenderCertificate, Timestamp};
use serde_json::{Value, json};

/// Com esta variável definida, o teste regrava o vetor antes de conferi-lo.
const UPDATE: &str = "FALAAI_UPDATE_VECTORS";

/// Commit da libsignal que gerou e que confere o vetor (Cargo.toml).
const LIBSIGNAL_REV: &str = "b2a5c30f3245c1bcad04b27b1e752a38321c793d";

/// Instante da validação: 2026-01-01T00:00:00Z. O certificado vale 24h a partir dele.
const VALIDATION_TIME: u64 = 1_767_225_600_000;
const VALIDITY: u64 = 24 * 60 * 60 * 1000;

const SERVER_KEY_ID: u32 = 1;
const ACI: [u8; 16] = [
    0x9d, 0x06, 0x52, 0xa3, 0xdc, 0xc3, 0x4d, 0x11, 0x97, 0x5f, 0x74, 0xd6, 0x15, 0x98, 0x73, 0x3f,
];
const ACI_STRING: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
const DEVICE_ID: u32 = 2;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/vectors/sender_certificate.json")
}

/// Um vetor novo, emitido pelo [`Signer`] com chaves geradas na hora.
fn generate() -> Result<Value, Box<dyn Error>> {
    let rng = &mut rand::rng();
    let generated = keys::generate(SERVER_KEY_ID, rng)?;
    let signer = Signer::new(SignerKeys::from_json(&generated.signer_secret)?);
    let identity = IdentityKeyPair::generate(rng);
    let identity_key = identity.identity_key().serialize();
    let expires_at = VALIDATION_TIME + VALIDITY;
    let certificate = signer.sign_sender_certificate(
        &SenderCertificateRequest {
            aci: &ACI,
            device_id: DEVICE_ID,
            identity_key: &identity_key,
            expires_at_millis: expires_at,
        },
        VALIDATION_TIME,
    )?;
    Ok(json!({
        "description": "SenderCertificate emitido pelo falaai-signer. Base64 padrão; tempos em ms desde a época Unix. Vale em validation_time e vence depois de expires_at. A identidade do remetente é só de teste.",
        "libsignal_rev": LIBSIGNAL_REV,
        "trust_root": STANDARD.encode(generated.trust_root_public),
        "server_certificate_key_id": SERVER_KEY_ID,
        "sender": {
            "aci": ACI_STRING,
            "aci_bytes": STANDARD.encode(ACI),
            "device_id": DEVICE_ID,
            "identity_key": STANDARD.encode(&identity_key),
            "identity_key_pair": STANDARD.encode(identity.serialize()),
        },
        "expires_at": expires_at,
        "validation_time": VALIDATION_TIME,
        "sender_certificate": STANDARD.encode(certificate),
    }))
}

fn field<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .pointer(pointer)
        .ok_or_else(|| format!("vetor sem {pointer}").into())
}

fn bytes(value: &Value, pointer: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = field(value, pointer)?
        .as_str()
        .ok_or_else(|| format!("{pointer} não é texto"))?;
    Ok(STANDARD.decode(text)?)
}

fn number(value: &Value, pointer: &str) -> Result<u64, Box<dyn Error>> {
    Ok(field(value, pointer)?
        .as_u64()
        .ok_or_else(|| format!("{pointer} não é número"))?)
}

/// Os nomes de campo, recursivamente, para comparar o formato de dois vetores.
fn shape(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), shape(value)))
                .collect(),
        ),
        _ => Value::Null,
    }
}

#[tokio::test]
async fn vetor_versionado_abre_no_sealed_sender_decrypt() -> TestResult {
    if std::env::var_os(UPDATE).is_some() {
        let mut json = serde_json::to_string_pretty(&generate()?)?;
        json.push('\n');
        std::fs::write(path(), json)?;
    }
    let vector: Value = serde_json::from_slice(&std::fs::read(path())?)?;
    assert_eq!(field(&vector, "/libsignal_rev")?, LIBSIGNAL_REV);

    let trust_root_bytes = bytes(&vector, "/trust_root")?;
    let trust_root = PublicKey::deserialize(&trust_root_bytes)?;
    let certificate_bytes = bytes(&vector, "/sender_certificate")?;
    let certificate = SenderCertificate::deserialize(&certificate_bytes)?;
    let validation_time = number(&vector, "/validation_time")?;
    let expires_at = number(&vector, "/expires_at")?;

    assert!(certificate.validate(&trust_root, Timestamp::from_epoch_millis(validation_time))?);
    assert!(!certificate.validate(&trust_root, Timestamp::from_epoch_millis(expires_at + 1))?);
    assert_eq!(certificate.expiration()?.epoch_millis(), expires_at);
    assert_eq!(
        certificate.sender_uuid()?,
        field(&vector, "/sender/aci")?.as_str().unwrap_or_default()
    );
    assert_eq!(bytes(&vector, "/sender/aci_bytes")?, ACI);
    assert_eq!(
        u64::from(u32::from(certificate.sender_device_id()?)),
        number(&vector, "/sender/device_id")?
    );
    assert_eq!(
        &*certificate.key()?.serialize(),
        bytes(&vector, "/sender/identity_key")?.as_slice()
    );
    assert_eq!(
        u64::from(certificate.signer()?.key_id()?),
        number(&vector, "/server_certificate_key_id")?
    );

    let identity =
        IdentityKeyPair::try_from(bytes(&vector, "/sender/identity_key_pair")?.as_slice())?;
    assert_eq!(
        &*identity.identity_key().serialize(),
        bytes(&vector, "/sender/identity_key")?.as_slice()
    );
    let opened = open_sealed(
        &trust_root_bytes,
        &certificate_bytes,
        identity,
        Timestamp::from_epoch_millis(validation_time),
    )
    .await?;
    assert_eq!(opened.message, PLAINTEXT);
    assert_eq!(opened.sender_uuid, ACI_STRING);
    Ok(())
}

#[test]
fn gerador_produz_o_formato_versionado() -> TestResult {
    let vector: Value = serde_json::from_slice(&std::fs::read(path())?)?;
    assert_eq!(
        shape(&generate()?),
        shape(&vector),
        "rode `make vectors` e revise o diff"
    );
    Ok(())
}
