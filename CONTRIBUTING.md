# Contributing

Thanks for helping improve OCT.

## Development

```sh
rustup toolchain install 1.93.1
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

Optional real-OpenCode gates:

```sh
./scripts/e2e-real-opencode.sh
./scripts/e2e-tui.py
./scripts/e2e-tui.py --e2ee
```

## Pull requests

- Keep changes focused and include tests for behavior changes.
- Do not log secrets, bodies, Authorization/Cookie headers, PTY tickets or
  invite URIs.
- Security-sensitive changes need a short threat-model note in the PR.
- Update public docs when CLI behavior or wire semantics change.
- Run `cargo fmt` and clippy before opening a PR.

## Commit style

Use clear imperative subjects, for example:

```text
relay: reject malformed binary before HELLO
client: retry on revoked device
docs: add Kubernetes deployment example
```

## Reporting security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).
