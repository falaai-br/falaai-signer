//! falaai-signer: assina os certificados do sealed sender com a libsignal (ADR-0011).
//!
//! O trust root assina, fora do serviço ([`keys::generate`]), o `ServerCertificate`. O serviço
//! carrega o trust root público, esse certificado e a chave privada dele ([`keys::SignerKeys`]),
//! e emite `SenderCertificate` de curta duração para o `accounts` por gRPC local
//! ([`server`]). Não há estado, banco nem log de requisições.

pub mod keys;
pub mod listen;
pub mod proto;
pub mod server;
pub mod signer;
