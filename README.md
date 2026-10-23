# falaai-signer

Serviço do **FalaAí** que assina certificados de remetente do sealed sender, usando a [libsignal](https://github.com/signalapp/libsignal). É um binário pequeno, chamado pelo módulo `accounts` do servidor por gRPC local, para que nenhuma criptografia seja escrita à mão e o restante do servidor não precise linkar código AGPL ([ADR-0011](https://github.com/falaai-br/falaai/blob/main/docs/adr/ADR-0011-servico-assinador-agpl.md)).

## Licença

AGPL-3.0. Ver [LICENSE](LICENSE).
