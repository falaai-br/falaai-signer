//! Gera o servidor e o cliente gRPC a partir de `proto/`. O protoc vem de `.tools/` (ver
//! `make protoc` e `.cargo/config.toml`).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        // O cliente serve aos testes e a quem usar o crate; sem transporte embutido, quem chama
        // escolhe o canal (TCP em loopback ou socket Unix).
        .build_transport(false)
        .compile_protos(&["proto/falaai/signer/v1/signer.proto"], &["proto"])?;
    Ok(())
}
