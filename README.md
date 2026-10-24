# falaai-signer

Serviço do **FalaAí** que assina certificados de remetente do sealed sender, usando a [libsignal](https://github.com/signalapp/libsignal). É um binário pequeno, chamado pelo módulo `accounts` do servidor por gRPC local, para que nenhuma criptografia seja escrita à mão e o restante do servidor não precise linkar código AGPL ([ADR-0011](https://github.com/falaai-br/falaai/blob/main/docs/adr/ADR-0011-servico-assinador-agpl.md)).

## Licença

AGPL-3.0. Ver [LICENSE](LICENSE).

## Como funciona

- O **trust root** assina, fora do serviço, o `ServerCertificate`. O serviço recebe só o trust root público, esse certificado e a chave privada dele, e confere na carga que o certificado encadeia até o trust root e que a chave é a do certificado. A chave privada do trust root nunca entra no pod.
- O `accounts` pede `SenderCertificate` de curta duração por gRPC (`falaai.signer.v1.SignerService`, em [`proto/`](proto/falaai/signer/v1/signer.proto)). `expires_at` precisa estar no futuro e a no máximo 7 dias da emissão.
- Sem estado, sem banco, sem log de requisição. Escuta só em socket Unix ou TCP em loopback.

## Executar

```sh
make tools                                         # toolchain, protoc pinado, ferramentas e hooks
cargo run -- keygen --key-id 1 --out /tmp/signer   # chaves de dev: trust-root.json e signer-secret.json
FALAAI_SIGNER_SECRET_FILE=/tmp/signer/signer-secret.json \
FALAAI_SIGNER_LISTEN=unix:/tmp/signer/signer.sock \
cargo run -- serve
```

| Variável | Valor |
|---|---|
| `FALAAI_SIGNER_LISTEN` | `unix:/caminho.sock` ou `127.0.0.1:porta` (padrão `127.0.0.1:50051`) |
| `FALAAI_SIGNER_SECRET_FILE` | arquivo JSON com `trust_root`, `server_certificate` e `server_private_key` (base64) |
| `FALAAI_SIGNER_SECRET` | o mesmo JSON, inline (ex.: injetado do Secrets Manager). Use um dos dois |

`trust-root.json` tem a chave privada do trust root: guarde fora do serviço. O trust root público vai embutido na build do app.

## Cliente Go

O `accounts` gera o cliente a partir de [`proto/`](proto/) com buf (`buf.yaml` na raiz, mesmas regras do falaai-proto), usando `go_package_prefix` no modo gerenciado.

## Vetores

[`testdata/vectors/`](testdata/vectors/README.md) tem um certificado emitido pelo signer, conferido aqui por `sealed_sender_decrypt` na libsignal do mesmo commit do falaai-core. Regerar com `make vectors`.
