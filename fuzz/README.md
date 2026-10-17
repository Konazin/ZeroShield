# Fuzz targets

Coverage-guided fuzzing (libFuzzer via `cargo-fuzz`) for the parsers that
consume untrusted input:

| target | parser |
|---|---|
| `ipc_frame` | newline-JSON IPC frames/requests (`zs-ipc`) |
| `feed_parse` | threat feed text (`zs-net`) |
| `rules_toml` | content rules TOML (`zs-scan`) |
| `sigs_import` | `.hdb` / CSV / plain hash imports (`zs-scan`) |
| `config_toml` | daemon config TOML (`zs-core`) |
| `elf_heuristics` | ELF static analysis of scanned files (`zs-scan`) |

Requires a nightly toolchain and `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
cargo fuzz run ipc_frame -- -max_total_time=60
```

The scheduled CI job (`fuzz`) runs every target for 60 s and fails on a
crash. On every PR, the deterministic mini-fuzzer tests
(`crates/*/tests/mini_fuzz.rs`, stable Rust) exercise the same parsers with
seeded random and mutated inputs.
