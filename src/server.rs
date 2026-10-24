//! Serviço gRPC `falaai.signer.v1.SignerService`. Nenhuma requisição é registrada em log.

use std::future::Future;
use std::io;
use std::os::unix::fs::FileTypeExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::{TcpListener, UnixListener};
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::{Request, Response, Status};

use crate::listen::ListenAddr;
use crate::proto::signer_service_server::{SignerService, SignerServiceServer};
use crate::proto::{
    GetTrustRootRequest, GetTrustRootResponse, SignSenderCertificateRequest,
    SignSenderCertificateResponse,
};
use crate::signer::{SenderCertificateRequest, SignError, Signer};

/// Maior requisição aceita. Uma `SignSenderCertificateRequest` válida tem menos de 100 bytes.
const MAX_REQUEST_BYTES: usize = 1024;

/// Implementação do serviço sobre um [`Signer`].
#[derive(Debug, Clone)]
pub struct SignerGrpc {
    signer: Arc<Signer>,
}

impl SignerGrpc {
    /// Serviço gRPC pronto para registrar num `tonic::transport::Server`.
    pub fn service(signer: Signer) -> SignerServiceServer<Self> {
        SignerServiceServer::new(Self {
            signer: Arc::new(signer),
        })
        .max_decoding_message_size(MAX_REQUEST_BYTES)
    }
}

#[tonic::async_trait]
impl SignerService for SignerGrpc {
    async fn sign_sender_certificate(
        &self,
        request: Request<SignSenderCertificateRequest>,
    ) -> Result<Response<SignSenderCertificateResponse>, Status> {
        let request = request.into_inner();
        let certificate = self
            .signer
            .sign_sender_certificate(
                &SenderCertificateRequest {
                    aci: &request.aci,
                    device_id: request.device_id,
                    identity_key: &request.identity_key,
                    expires_at_millis: request.expires_at,
                },
                now_millis()?,
            )
            .map_err(status)?;
        Ok(Response::new(SignSenderCertificateResponse { certificate }))
    }

    async fn get_trust_root(
        &self,
        _request: Request<GetTrustRootRequest>,
    ) -> Result<Response<GetTrustRootResponse>, Status> {
        Ok(Response::new(GetTrustRootResponse {
            public_key: self.signer.trust_root(),
        }))
    }
}

fn status(error: SignError) -> Status {
    match error {
        SignError::Signing => Status::internal(error.to_string()),
        SignError::InvalidAci
        | SignError::InvalidDeviceId
        | SignError::InvalidIdentityKey
        | SignError::InvalidExpiration => Status::invalid_argument(error.to_string()),
    }
}

fn now_millis() -> Result<u64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|now| u64::try_from(now.as_millis()).ok())
        .ok_or_else(|| Status::internal("relógio do sistema inválido"))
}

/// Socket já aberto em [`ListenAddr`].
#[derive(Debug)]
pub enum Listener {
    /// TCP em loopback.
    Tcp(TcpListener),
    /// Socket Unix; o arquivo é removido quando o serviço termina.
    Unix(UnixListener, PathBuf),
}

impl Listener {
    /// Abre o socket. Um socket Unix antigo no mesmo caminho (de um processo que morreu) é
    /// substituído; qualquer outro tipo de arquivo no caminho é erro.
    pub async fn bind(address: &ListenAddr) -> io::Result<Self> {
        match address {
            ListenAddr::Tcp(address) => Ok(Self::Tcp(TcpListener::bind(address).await?)),
            ListenAddr::Unix(path) => {
                match std::fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)?,
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "o caminho do socket já existe e não é um socket",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                Ok(Self::Unix(UnixListener::bind(path)?, path.clone()))
            }
        }
    }
}

/// Serve `signer` em `listener` até `shutdown` completar.
pub async fn serve<F>(
    signer: Signer,
    listener: Listener,
    shutdown: F,
) -> Result<(), tonic::transport::Error>
where
    F: Future<Output = ()> + Send,
{
    let router = tonic::transport::Server::builder().add_service(SignerGrpc::service(signer));
    match listener {
        Listener::Tcp(listener) => {
            router
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
                .await
        }
        Listener::Unix(listener, path) => {
            let result = router
                .serve_with_incoming_shutdown(UnixListenerStream::new(listener), shutdown)
                .await;
            // Melhor esforço: o próximo bind também substitui um socket que tenha ficado.
            let _ = std::fs::remove_file(path);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erros_de_requisicao_viram_invalid_argument_e_o_resto_internal() {
        for error in [
            SignError::InvalidAci,
            SignError::InvalidDeviceId,
            SignError::InvalidIdentityKey,
            SignError::InvalidExpiration,
        ] {
            assert_eq!(status(error).code(), tonic::Code::InvalidArgument);
        }
        assert_eq!(status(SignError::Signing).code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn bind_recusa_caminho_que_nao_e_socket() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("arquivo");
        std::fs::write(&path, b"")?;
        let error = Listener::bind(&ListenAddr::Unix(path.clone())).await.err();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert!(path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn bind_substitui_socket_antigo() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("signer.sock");
        let old = std::os::unix::net::UnixListener::bind(&path)?;
        drop(old);
        let listener = Listener::bind(&ListenAddr::Unix(path.clone())).await?;
        assert!(matches!(listener, Listener::Unix(..)));
        Ok(())
    }
}
