# Contributing to Memoswish Server

Use an issue for a reproducible bug or a proposed change. Describe the affected version, operating system, configuration, and expected behavior. Remove credentials and private data from examples. Report vulnerabilities using the process in [SECURITY.md](SECURITY.md).

Keep the HTTP and MCP transports behind the shared application interfaces. Business crates should depend on the traits in `memoswish-core` for storage and external services. Add new paired migrations for SQLite and PostgreSQL and preserve existing migrations.

Run `make supply-chain-check` to check the exception ledger and locked dependencies. Remove exceptions when their fix lands, or renew them before the UTC expiry with fresh review evidence for the exact locked version and dependency edges.

Run `make server-check` before opening a pull request. Add focused tests for behavior changes. For wire changes, run `make contracts`, review the generated schema and fixture diff, and coordinate corresponding updates in the [app repository](https://github.com/getio0909/memoswish-app).

Follow the [code of conduct](CODE_OF_CONDUCT.md) in issues and reviews.
