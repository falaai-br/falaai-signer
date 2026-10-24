//! Binário do falaai-signer (ADR-0011).
//!
//! - `falaai-signer [serve]`: sobe o gRPC local. Configuração por ambiente:
//!   - `FALAAI_SIGNER_LISTEN`: `unix:/caminho.sock` ou `127.0.0.1:porta` (padrão
//!     `127.0.0.1:50051`). Só loopback ou socket Unix.
//!   - `FALAAI_SIGNER_SECRET_FILE` (arquivo) ou `FALAAI_SIGNER_SECRET` (o JSON em si, como vem do
//!     Secrets Manager): o segredo descrito em `falaai_signer::keys`. Exatamente um dos dois.
//! - `falaai-signer keygen --key-id <id> --out <dir>`: gera trust root e chave de servidor de dev
//!   em `<dir>/trust-root.json` e `<dir>/signer-secret.json` (modo 0600, sem sobrescrever).

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use falaai_signer::keys::{self, SignerKeys};
use falaai_signer::listen::ListenAddr;
use falaai_signer::server::{self, Listener};
use falaai_signer::signer::Signer;
use zeroize::Zeroizing;

const DEFAULT_LISTEN: &str = "127.0.0.1:50051";
const USAGE: &str = "uso:
  falaai-signer [serve]
      FALAAI_SIGNER_LISTEN       unix:/caminho.sock ou 127.0.0.1:porta (padrão 127.0.0.1:50051)
      FALAAI_SIGNER_SECRET_FILE  arquivo JSON com o segredo, ou
      FALAAI_SIGNER_SECRET       o JSON do segredo
  falaai-signer keygen --key-id <id> --out <dir>
      gera trust-root.json e signer-secret.json de dev em <dir>";

type CliResult = Result<(), Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None | Some("serve") if args.len() <= 1 => serve(),
        Some("keygen") => keygen(args.get(1..).unwrap_or_default()),
        Some("-h" | "--help" | "help") => {
            eprintln!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("falaai-signer: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serve() -> CliResult {
    let listen: ListenAddr = std::env::var("FALAAI_SIGNER_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
        .parse()?;
    let keys = SignerKeys::from_json(&secret()?)?;
    let signer = Signer::new(keys);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = Listener::bind(&listen).await?;
        eprintln!("falaai-signer: ouvindo em {listen}");
        server::serve(signer, listener, shutdown_signal()).await?;
        eprintln!("falaai-signer: encerrado");
        Ok(())
    })
}

/// Segredo do serviço, do arquivo ou da variável de ambiente.
fn secret() -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let file = std::env::var_os("FALAAI_SIGNER_SECRET_FILE");
    let inline = std::env::var("FALAAI_SIGNER_SECRET")
        .ok()
        .map(Zeroizing::new);
    match (file, inline) {
        (Some(path), None) => Ok(Zeroizing::new(std::fs::read(&path).map_err(|error| {
            format!("não foi possível ler FALAAI_SIGNER_SECRET_FILE: {error}")
        })?)),
        (None, Some(json)) => Ok(Zeroizing::new(json.as_bytes().to_vec())),
        _ => Err("defina exatamente um de FALAAI_SIGNER_SECRET_FILE e FALAAI_SIGNER_SECRET".into()),
    }
}

/// Completa no SIGTERM (fim do pod) ou no Ctrl-C.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

fn keygen(args: &[String]) -> CliResult {
    let mut key_id = None;
    let mut out = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match (flag.as_str(), args.next()) {
            ("--key-id", Some(value)) => key_id = Some(value.parse::<u32>()?),
            ("--out", Some(value)) => out = Some(Path::new(value)),
            _ => return Err(USAGE.into()),
        }
    }
    let (Some(key_id), Some(out)) = (key_id, out) else {
        return Err(USAGE.into());
    };

    let generated = keys::generate(key_id, &mut rand::rng())?;
    let trust_root_path = out.join("trust-root.json");
    let secret_path = out.join("signer-secret.json");
    write_private(&trust_root_path, &generated.trust_root)?;
    write_private(&secret_path, &generated.signer_secret)?;
    eprintln!(
        "falaai-signer: gerados {} (guardar fora do serviço) e {} (FALAAI_SIGNER_SECRET_FILE)",
        trust_root_path.display(),
        secret_path.display()
    );
    eprintln!(
        "falaai-signer: trust root público (base64, vai na build do app): {}",
        STANDARD.encode(&generated.trust_root_public)
    );
    Ok(())
}

/// Grava um arquivo novo legível só pelo dono. Recusa sobrescrever.
fn write_private(path: &Path, contents: &[u8]) -> CliResult {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}
