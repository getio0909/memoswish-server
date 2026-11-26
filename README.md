[简体中文](README.zh-CN.md)

# Memoswish Server

[![CI](https://github.com/getio0909/memoswish-server/actions/workflows/server.yml/badge.svg)](https://github.com/getio0909/memoswish-server/actions/workflows/server.yml) [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Website and docs: <https://getio0909.github.io/memoswish-website/>

The Rust server for Memoswish (忆刷), a swipe-based microlearning app.

The project is in pre-1.0 development. The server provides the app's HTTP API, generates review feeds with FSRS, and lets users import Anki decks and Memoswish DeckPacks. MCP clients can manage learning content over stdio or Streamable HTTP. By default, the server uses SQLite and local asset storage. Other deployments can use PostgreSQL and S3-compatible storage.

## Requirements

You need stable Rust with Cargo, rustfmt, and Clippy. The verified toolchain is Rust 1.100.0. The build also needs a C/C++ toolchain and CMake. The commands below use GNU Make and curl.

## Quick start

Run this from the repository root.

```sh
make run-server
```

The server listens on `127.0.0.1:8787` and seeds demo cards on first startup. From another terminal, check that it is running.

```sh
curl --fail http://127.0.0.1:8787/v1/server-info
```

Connect with the [Memoswish app](https://github.com/getio0909/memoswish-app). To launch the server from a local MCP client, use `make mcp-stdio`.

## Configuration

Start with [the embedded configuration example](server/config/memoswishd.example.toml) and pass it to `memoswishd` with the global `--config` flag. Where an override is available, CLI flags take precedence over environment variables, which take precedence over the TOML file and built-in defaults. Single-user mode grants access without login, so keep the default bind address for local development. Speech synthesis is unconfigured by default.

[The horizontal configuration example](server/config/memoswishd.horizontal.example.toml) requires external PostgreSQL, Redis, and S3-compatible object storage. Optional authentication, speech, and mail providers need their own configuration.

## Build and test

Run these from the repository root.

```sh
cargo build --locked --manifest-path server/Cargo.toml -p memoswishd
make server-check
```

The default workspace tests use SQLite. Ignored integration tests have separate prerequisites, such as PostgreSQL, Redis, espeak-ng, or backup utilities.

## Layout

- `server/` contains the Cargo workspace, configuration examples, and container files.
- `protocol/` contains the JSON schemas and wire fixtures. `compatibility/` contains the historical protocol and migration fixtures.
- `brand/` provides shared build metadata. `scripts/` provides test and backup utilities.
- `deploy/` contains single-instance service, reverse-proxy, and monitoring examples.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). See [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) for dependency notices. Brand artwork in this repository is under the same license. The license does not grant permission to use the Memoswish name or logo as a trademark (section 6).
