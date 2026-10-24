//! O binário: `keygen` grava as chaves de dev e `serve` sobe com elas e encerra no SIGTERM.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::TestResult;
use falaai_signer::proto::GetTrustRootRequest;
use falaai_signer::proto::signer_service_client::SignerServiceClient;

const BINARY: &str = env!("CARGO_BIN_EXE_falaai-signer");

fn keygen(out: &Path) -> std::io::Result<std::process::Output> {
    Command::new(BINARY)
        .args(["keygen", "--key-id", "3", "--out"])
        .arg(out)
        .output()
}

/// Encerra o processo filho se o teste falhar no meio.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn keygen_grava_arquivos_privados_e_nao_sobrescreve() -> TestResult {
    let dir = tempfile::tempdir()?;
    let output = keygen(dir.path())?;
    assert!(output.status.success(), "{output:?}");
    for name in ["trust-root.json", "signer-secret.json"] {
        let mode = std::fs::metadata(dir.path().join(name))?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
    let before = std::fs::read(dir.path().join("signer-secret.json"))?;
    let again = keygen(dir.path())?;
    assert!(!again.status.success());
    assert_eq!(
        std::fs::read(dir.path().join("signer-secret.json"))?,
        before
    );
    Ok(())
}

#[test]
fn serve_recusa_configuracao_invalida() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(keygen(dir.path())?.status.success());
    let secret = dir.path().join("signer-secret.json");
    let cases: [(&[(&str, &str)], &str); 3] = [
        (&[], "FALAAI_SIGNER_SECRET"),
        (&[("FALAAI_SIGNER_SECRET", "{}")], "segredo malformado"),
        (&[("FALAAI_SIGNER_LISTEN", "0.0.0.0:50051")], "loopback"),
    ];
    for (env, expected) in cases {
        let mut command = Command::new(BINARY);
        command
            .env_remove("FALAAI_SIGNER_SECRET")
            .env_remove("FALAAI_SIGNER_SECRET_FILE")
            .env_remove("FALAAI_SIGNER_LISTEN");
        if expected == "loopback" {
            command.env("FALAAI_SIGNER_SECRET_FILE", &secret);
        }
        let output = command.envs(env.iter().copied()).output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{env:?}");
        assert!(stderr.contains(expected), "{env:?}: {stderr}");
    }
    Ok(())
}

#[tokio::test]
async fn serve_responde_com_o_trust_root_gerado_e_encerra_no_sigterm() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(keygen(dir.path())?.status.success());
    let socket = dir.path().join("signer.sock");
    let child = Command::new(BINARY)
        .arg("serve")
        .env_remove("FALAAI_SIGNER_SECRET")
        .env(
            "FALAAI_SIGNER_SECRET_FILE",
            dir.path().join("signer-secret.json"),
        )
        .env("FALAAI_SIGNER_LISTEN", format!("unix:{}", socket.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = KillOnDrop(child);

    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        if Instant::now() > deadline || child.0.try_wait()?.is_some() {
            return Err("o serviço não abriu o socket".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut client = SignerServiceClient::new(common::connect(&socket).await?);
    let trust_root = client
        .get_trust_root(GetTrustRootRequest {})
        .await?
        .into_inner()
        .public_key;
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("trust-root.json"))?)?;
    let expected = STANDARD.decode(document["public_key"].as_str().ok_or("public_key")?)?;
    assert_eq!(trust_root, expected);
    drop(client);

    let status = Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()?;
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(20);
    let exit = loop {
        if let Some(exit) = child.0.try_wait()? {
            break exit;
        }
        if Instant::now() > deadline {
            return Err("o serviço não encerrou no SIGTERM".into());
        }
        // Sleep do tokio: o runtime do teste precisa rodar para a conexão do cliente receber o
        // GOAWAY do encerramento gracioso e fechar.
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(exit.success(), "{exit:?}");
    assert!(!socket.exists());
    Ok(())
}
