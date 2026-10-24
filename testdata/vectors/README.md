# Vetores de certificado

`sender_certificate.json`: um `SenderCertificate` emitido pelo falaai-signer, com o trust root público e a identidade (de teste) do remetente. Base64 padrão; tempos em milissegundos desde a época Unix.

- O certificado encadeia até `trust_root`, vale em `validation_time` e vence depois de `expires_at`.
- `sender.identity_key_pair` é o `IdentityKeyPair` serializado pela libsignal, para o teste poder selar uma mensagem como o remetente. Só existe para teste.
- `libsignal_rev` é o commit da libsignal que gerou o vetor; o falaai-core pina o mesmo.

Quem consome: `tests/certificate_vectors.rs` deste repositório abre um sealed sender com o certificado por `sealed_sender_decrypt`. O falaai-core pode ler o mesmo arquivo para validar do lado dele.

Regerar com `make vectors` e revisar o diff. As assinaturas são aleatórias, então regerar sempre muda os bytes.
