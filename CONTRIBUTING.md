# Contributing to Memoswish Server

Use an issue for a reproducible bug or a proposed change. Describe the affected version, operating system, configuration, and expected behavior. Remove credentials and private data from examples. Report vulnerabilities using the process in [SECURITY.md](SECURITY.md).

Keep the HTTP and MCP transports behind the shared application interfaces. Business crates should depend on the traits in `memoswish-core` for storage and external services. Add new paired migrations for SQLite and PostgreSQL and preserve existing migrations.

Run `make supply-chain-check` to check the exception ledger and locked dependencies. Remove exceptions when their fix lands, or renew them before the UTC expiry with fresh review evidence for the exact locked version and dependency edges.

Run `make server-check` before opening a pull request. Add focused tests for behavior changes. For wire changes, run `make contracts`, review the generated schema and fixture diff, and coordinate corresponding updates in the [app repository](https://github.com/getio0909/memoswish-app).

CI runs `make server-lint` and `make server-test` separately on Rust 1.100.0. To check the minimum supported compiler, run `cargo +1.88.0 check --locked --workspace --all-targets` from `server/`.

Run `make server-integration` from a Git checkout with a commit at HEAD. Set `MEMOSWISH_TEST_POSTGRES_URL` to a disposable PostgreSQL database whose user can create databases and `MEMOSWISH_TEST_REDIS_URL` to a dedicated Redis instance on 127.0.0.1 on a port other than 6379. The suite creates and removes database fixtures and flushes the Redis script cache. CI uses PostgreSQL 17 and Redis 7. Install espeak-ng, the PostgreSQL client tools for that server version, sqlite3, Node.js 24, Git, GNU coreutils, binutils and flock. Run one integration suite at a time against those services.

Follow the [code of conduct](CODE_OF_CONDUCT.md) in issues and reviews.

## Releases

Run the **Server release** workflow manually to build both native Linux archives, the CycloneDX SBOM and both container images. A manual run ends before upload or publication, including when you select a tag.

Tag the tested public commit with the workspace version in `server/Cargo.toml`. For version 1.0.0, use `v1.0.0-rc.1` for a release candidate. Push that tag explicitly with `git push origin v1.0.0-rc.1`. Use `v1.0.0` when promoting a final release. Each tag builds on Debian 12 with Rust 1.100.0, tests the daemon on x86_64 and aarch64, and checks that both binaries load on Ubuntu 22.04. The container uses the version without the leading `v`. Only a final release updates `latest`.

Download both archives, the daemon SBOM and `SHA256SUMS` from the same GitHub Release. Run `gh attestation verify SHA256SUMS --repo getio0909/memoswish-server`, then `sha256sum -c SHA256SUMS`. You can verify either tarball directly with the same `gh attestation verify` command. The release notes give the exact image digest for `gh attestation verify oci://ghcr.io/getio0909/memoswish-server@sha256:… --repo getio0909/memoswish-server` and for pulling the verified index. Its native images carry BuildKit SBOM and provenance attestations. The downloadable CycloneDX document covers the daemon's Cargo dependencies across targets.

The Sigstore provenance bundle is attached to the release. To verify a downloaded file against that bundle, add `--bundle memoswishd-<version>.sigstore.json` to the file's verification command.
