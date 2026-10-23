.PHONY: fmt fmt-check clippy test check bench e2e e2e-tui e2e-e2ee fuzz deny release install clean

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

check:
	cargo check --workspace --all-targets

bench:
	cargo bench -p oct-protocol

e2e:
	./scripts/e2e-real-opencode.sh

e2e-tui:
	./scripts/e2e-tui.py

e2e-e2ee:
	./scripts/e2e-tui.py --e2ee

fuzz:
	cargo +nightly fuzz run wire -- -runs=100000
	cargo +nightly fuzz run security -- -runs=100000

deny:
	cargo deny check

release:
	cargo build --workspace --release

install:
	cargo install --path crates/oct-cli --locked

clean:
	cargo clean
