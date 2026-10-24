//! Apoio aos testes de integração: o signer servindo por socket Unix e um par de dispositivos da
//! libsignal (mesmo commit do falaai-core) que abre um sealed sender com o certificado emitido.
// Cada binário de teste usa só parte disto.
#![allow(dead_code)]

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use falaai_signer::keys::{self, SignerKeys};
use falaai_signer::listen::ListenAddr;
use falaai_signer::proto::signer_service_client::SignerServiceClient;
use falaai_signer::server::{self, Listener};
use falaai_signer::signer::Signer;
use hyper_util::rt::TokioIo;
use libsignal_protocol::{
    DeviceId, GenericSignedPreKey as _, IdentityKeyPair, IdentityKeyStore as _,
    InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore as _, PreKeyBundle,
    PreKeyRecord, PreKeyStore as _, ProtocolAddress, PublicKey, SealedSenderDecryptionResult,
    SenderCertificate, SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore as _, Timestamp,
    kem, process_prekey_bundle, sealed_sender_decrypt, sealed_sender_encrypt,
};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tonic::transport::{Channel, Endpoint, Uri};

pub type TestResult = Result<(), Box<dyn Error>>;

/// Mensagem selada nos testes.
pub const PLAINTEXT: &[u8] = b"oi do falaai-signer";

/// ACI do destinatário (texto, como no `ProtocolAddress`).
const RECIPIENT_ACI: &str = "2f3b1a6e-6c0e-4a8f-9c51-7e0d2b4f8a10";

/// Signer rodando numa tarefa, num socket Unix de um diretório temporário.
pub struct RunningSigner {
    pub client: SignerServiceClient<Channel>,
    pub trust_root: Vec<u8>,
    socket: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    _dir: tempfile::TempDir,
}

impl RunningSigner {
    /// Gera chaves de dev, sobe o serviço e conecta um cliente.
    pub async fn start() -> Result<Self, Box<dyn Error>> {
        let generated = keys::generate(1, &mut rand::rng())?;
        let signer = Signer::new(SignerKeys::from_json(&generated.signer_secret)?);
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("signer.sock");
        let listener = Listener::bind(&ListenAddr::Unix(socket.clone())).await?;
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(server::serve(signer, listener, async {
            let _ = stopped.await;
        }));
        let client = SignerServiceClient::new(connect(&socket).await?);
        Ok(Self {
            client,
            trust_root: generated.trust_root_public,
            socket,
            stop: Some(stop),
            task,
            _dir: dir,
        })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Para o serviço e espera a tarefa terminar.
    pub async fn stop(mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        (&mut self.task).await??;
        Ok(())
    }
}

/// Canal gRPC pelo socket Unix em `path`.
pub async fn connect(path: &Path) -> Result<Channel, Box<dyn Error>> {
    let path = path.to_owned();
    // O URI só é usado nos cabeçalhos HTTP/2; a conexão vai pelo socket.
    Ok(Endpoint::try_from("http://signer.local")?
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await?)
}

/// O remetente (com a identidade `sender_identity` e o certificado `certificate`) sela
/// [`PLAINTEXT`] para um destinatário novo, que abre com `sealed_sender_decrypt` validando o
/// certificado contra `trust_root` no instante `validation_time`. É o que o falaai-core faz.
pub async fn open_sealed(
    trust_root: &[u8],
    certificate: &[u8],
    sender_identity: IdentityKeyPair,
    validation_time: Timestamp,
) -> Result<SealedSenderDecryptionResult, SignalProtocolError> {
    let rng = &mut rand::rng();
    let trust_root = PublicKey::deserialize(trust_root)?;
    let certificate = SenderCertificate::deserialize(certificate)?;
    let sender_address = ProtocolAddress::new(
        certificate.sender_uuid()?.to_owned(),
        certificate.sender_device_id()?,
    );
    let recipient_device = device(1)?;
    let recipient_address = ProtocolAddress::new(RECIPIENT_ACI.to_owned(), recipient_device);

    let mut sender = InMemSignalProtocolStore::new(sender_identity, 1)?;
    let mut recipient = InMemSignalProtocolStore::new(IdentityKeyPair::generate(rng), 2)?;
    let bundle = pre_key_bundle(&mut recipient, recipient_device).await?;
    process_prekey_bundle(
        &recipient_address,
        &sender_address,
        &mut sender.session_store,
        &mut sender.identity_store,
        &bundle,
        SystemTime::now(),
        rng,
    )
    .await?;
    let sealed = sealed_sender_encrypt(
        &recipient_address,
        &certificate,
        PLAINTEXT,
        &mut sender.session_store,
        &mut sender.identity_store,
        SystemTime::now(),
        rng,
    )
    .await?;
    sealed_sender_decrypt(
        &sealed,
        &trust_root,
        validation_time,
        None,
        RECIPIENT_ACI.to_owned(),
        recipient_device,
        &mut recipient.identity_store,
        &mut recipient.session_store,
        &mut recipient.pre_key_store,
        &recipient.signed_pre_key_store,
        &mut recipient.kyber_pre_key_store,
    )
    .await
}

fn device(id: u8) -> Result<DeviceId, SignalProtocolError> {
    DeviceId::new(id).map_err(|_| SignalProtocolError::InvalidArgument("device id".to_owned()))
}

/// Bundle PQXDH do destinatário, com as pré-chaves gravadas no store dele. Adaptado de
/// `rust/protocol/tests/support` da libsignal.
async fn pre_key_bundle(
    store: &mut InMemSignalProtocolStore,
    device_id: DeviceId,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let rng = &mut rand::rng();
    let identity = store.identity_store.get_identity_key_pair().await?;
    let pre_key = KeyPair::generate(rng);
    let signed_pre_key = KeyPair::generate(rng);
    let kyber_pre_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let signed_signature = identity
        .private_key()
        .calculate_signature(&signed_pre_key.public_key.serialize(), rng)?;
    let kyber_signature = identity
        .private_key()
        .calculate_signature(&kyber_pre_key.public_key.serialize(), rng)?;

    let bundle = PreKeyBundle::new(
        store.identity_store.get_local_registration_id().await?,
        device_id,
        Some((1.into(), pre_key.public_key)),
        2.into(),
        signed_pre_key.public_key,
        signed_signature.to_vec(),
        3.into(),
        kyber_pre_key.public_key.clone(),
        kyber_signature.to_vec(),
        *identity.identity_key(),
    )?;
    let created = Timestamp::from_epoch_millis(0);
    store
        .pre_key_store
        .save_pre_key(1.into(), &PreKeyRecord::new(1.into(), &pre_key))
        .await?;
    store
        .signed_pre_key_store
        .save_signed_pre_key(
            2.into(),
            &SignedPreKeyRecord::new(2.into(), created, &signed_pre_key, &signed_signature),
        )
        .await?;
    store
        .kyber_pre_key_store
        .save_kyber_pre_key(
            3.into(),
            &KyberPreKeyRecord::new(3.into(), created, &kyber_pre_key, &kyber_signature),
        )
        .await?;
    Ok(bundle)
}
