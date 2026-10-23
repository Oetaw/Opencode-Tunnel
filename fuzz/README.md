# OCT fuzz targets

These targets are not part of the Cargo workspace. Install `cargo-fuzz` and a
nightly toolchain, then run from the repository root:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run wire -- -runs=100000
cargo +nightly fuzz run security -- -runs=100000
```

The seed corpus should contain valid frame/HTTP/WS/HELLO/invite fixtures. CI
runs a short smoke campaign on a schedule; a real campaign needs hours/days and
an independent review of any crashes.
