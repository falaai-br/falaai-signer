//! O serviço gRPC de ponta a ponta: o certificado emitido abre um sealed sender na libsignal do
//! mesmo commit do falaai-core, e só nas condições certas.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use common::{PLAINTEXT, RunningSigner, TestResult, open_sealed};
use falaai_signer::proto::{GetTrustRootRequest, SignSenderCertificateRequest};
use libsignal_protocol::{IdentityKeyPair, Timestamp};

const ACI: [u8; 16] = [
    0x9d, 0x06, 0x52, 0xa3, 0xdc, 0xc3, 0x4d, 0x11, 0x97, 0x5f, 0x74, 0xd6, 0x15, 0x98, 0x73, 0x3f,
];
const ACI_STRING: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;

fn now_millis() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn request(identity: &IdentityKeyPair, expires_at: u64) -> SignSenderCertificateRequest {
    SignSenderCertificateRequest {
        aci: ACI.to_vec(),
        device_id: 2,
        identity_key: identity.identity_key().serialize().to_vec(),
        expires_at,
    }
}

#[tokio::test]
async fn certificado_emitido_abre_no_sealed_sender_decrypt() -> TestResult {
    let mut signer = RunningSigner::start().await?;
    let trust_root = signer
        .client
        .get_trust_root(GetTrustRootRequest {})
        .await?
        .into_inner()
        .public_key;
    assert_eq!(trust_root, signer.trust_root);

    let identity = IdentityKeyPair::generate(&mut rand::rng());
    let now = now_millis()?;
    let certificate = signer
        .client
        .sign_sender_certificate(request(&identity, now + DAY_MILLIS))
        .await?
        .into_inner()
        .certificate;

    let opened = open_sealed(
        &trust_root,
        &certificate,
        identity,
        Timestamp::from_epoch_millis(now),
    )
    .await?;
    assert_eq!(opened.message, PLAINTEXT);
    assert_eq!(opened.sender_uuid, ACI_STRING);
    assert_eq!(opened.sender_e164, None);
    assert_eq!(u32::from(opened.device_id), 2);
    signer.stop().await
}

#[tokio::test]
async fn sealed_sender_decrypt_recusa_fora_das_condicoes() -> TestResult {
    let mut signer = RunningSigner::start().await?;
    let identity = IdentityKeyPair::generate(&mut rand::rng());
    let now = now_millis()?;
    let expires_at = now + DAY_MILLIS;
    let certificate = signer
        .client
        .sign_sender_certificate(request(&identity, expires_at))
        .await?
        .into_inner()
        .certificate;
    let valid_time = Timestamp::from_epoch_millis(now);

    // Vencido.
    let expired = Timestamp::from_epoch_millis(expires_at + 1);
    assert!(
        open_sealed(&signer.trust_root, &certificate, identity, expired)
            .await
            .is_err()
    );
    // Outro trust root.
    let other = RunningSigner::start().await?;
    assert!(
        open_sealed(&other.trust_root, &certificate, identity, valid_time)
            .await
            .is_err()
    );
    // Certificado de outra identidade: a chave do selo não bate com a do certificado.
    let impostor = IdentityKeyPair::generate(&mut rand::rng());
    assert!(
        open_sealed(&signer.trust_root, &certificate, impostor, valid_time)
            .await
            .is_err()
    );
    // Controle: nas condições certas abre.
    assert!(
        open_sealed(&signer.trust_root, &certificate, identity, valid_time)
            .await
            .is_ok()
    );

    other.stop().await?;
    signer.stop().await
}

#[tokio::test]
async fn requisicao_invalida_vira_invalid_argument_sem_ecoar_o_aci() -> TestResult {
    let mut signer = RunningSigner::start().await?;
    let identity = IdentityKeyPair::generate(&mut rand::rng());
    let now = now_millis()?;
    let valid = request(&identity, now + DAY_MILLIS);
    let cases = [
        SignSenderCertificateRequest {
            aci: ACI[..8].to_vec(),
            ..valid.clone()
        },
        SignSenderCertificateRequest {
            device_id: 0,
            ..valid.clone()
        },
        SignSenderCertificateRequest {
            identity_key: vec![5; 10],
            ..valid.clone()
        },
        // Segundos em vez de milissegundos.
        SignSenderCertificateRequest {
            expires_at: (now + DAY_MILLIS) / 1000,
            ..valid.clone()
        },
        SignSenderCertificateRequest {
            expires_at: 0,
            ..valid.clone()
        },
    ];
    for case in cases {
        let status = signer
            .client
            .sign_sender_certificate(case)
            .await
            .err()
            .ok_or("requisição inválida aceita")?;
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status:?}");
        assert!(!status.message().contains(ACI_STRING), "{status:?}");
        assert!(!status.message().contains("9d0652a3"), "{status:?}");
    }
    signer.stop().await
}

#[tokio::test]
async fn requisicao_grande_demais_e_recusada() -> TestResult {
    let mut signer = RunningSigner::start().await?;
    let identity = IdentityKeyPair::generate(&mut rand::rng());
    let oversized = SignSenderCertificateRequest {
        aci: vec![0; 4096],
        ..request(&identity, now_millis()? + DAY_MILLIS)
    };
    let status = signer
        .client
        .sign_sender_certificate(oversized)
        .await
        .err()
        .ok_or("requisição grande demais aceita")?;
    assert_ne!(status.code(), tonic::Code::Ok);
    assert_ne!(status.code(), tonic::Code::InvalidArgument, "{status:?}");
    signer.stop().await
}

#[tokio::test]
async fn ao_parar_remove_o_socket() -> TestResult {
    let signer = RunningSigner::start().await?;
    let socket = signer.socket().to_owned();
    assert!(socket.exists());
    signer.stop().await?;
    assert!(!socket.exists());
    Ok(())
}
