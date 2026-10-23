# falaai-signer — pipeline de qualidade.
include mk/hooks.mk

CARGO_DENY_VERSION  ?= 0.20.2
CARGO_AUDIT_VERSION ?= 0.22.2
GITLEAKS ?= $(shell command -v gitleaks || echo $(HOME)/go/bin/gitleaks)

.PHONY: tools fmt lint test test-integration security build check check-fast
tools: hooks ## Instala toolchain e ferramentas pinadas e ativa os hooks
	@command -v rustup >/dev/null || { echo "instale rustup: https://rustup.rs"; exit 1; }
	rustup show active-toolchain
	rustup component add rustfmt clippy
	cargo install --locked cargo-deny@$(CARGO_DENY_VERSION) cargo-audit@$(CARGO_AUDIT_VERSION)

fmt: ## Formata
	cargo fmt --all

lint: ## rustfmt check e clippy estrito
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features --locked -- -D warnings

test: ## Testes unitários
	cargo test --lib --locked

test-integration: ## Testes de integração (dois cores trocando mensagens, SQLCipher real)
	cargo test --test '*' --locked

security: ## cargo-deny (licenças, advisories, fontes), cargo-audit, gitleaks
	cargo deny --locked check
	cargo audit
	$(GITLEAKS) git --no-banner --redact .

build: ## Build de release do host
	cargo build --release --locked


check-fast: ## pre-commit
	cargo fmt --all -- --check
	cargo clippy --lib --locked -- -D warnings
	$(GITLEAKS) git --no-banner --redact --staged .

check: lint test test-integration security build ## pre-push e gate do Refinery
