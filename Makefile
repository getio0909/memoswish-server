CARGO ?= cargo

.DEFAULT_GOAL := help
.PHONY: help server-fmt server-lint server-test server-check run-server mcp-stdio contracts contracts-check supply-chain-check

help:
	@printf '%s\n' \
	  'server-fmt       Format the Rust workspace' \
	  'server-lint      Check formatting and run Clippy' \
	  'server-test      Run the workspace tests using SQLite' \
	  'server-check     Run lint and tests' \
	  'run-server       Start the local SQLite server with demo data' \
	  'mcp-stdio        Start the MCP server over standard input and output' \
	  'contracts        Regenerate protocol schemas and fixtures' \
	  'contracts-check  Verify generated protocol schemas and fixtures' \
	  'supply-chain-check  Validate exception expiry and check locked dependencies'

server-fmt:
	cd server && $(CARGO) fmt --all

server-lint:
	cd server && $(CARGO) fmt --all --check
	cd server && $(CARGO) clippy --locked --workspace --all-targets --all-features -- -D warnings

server-test:
	cd server && $(CARGO) test --workspace

server-check: server-lint server-test

run-server:
	cd server && $(CARGO) run --locked -p memoswishd -- serve

mcp-stdio:
	cd server && $(CARGO) run --locked -q -p memoswishd -- mcp-stdio

contracts:
	cd server && MEMOSWISH_BLESS=1 $(CARGO) test --locked -p memoswish-protocol committed_contracts_are_up_to_date

contracts-check:
	cd server && $(CARGO) test --locked -p memoswish-protocol committed_contracts_are_up_to_date

supply-chain-check:
	node scripts/supply-chain-policy.mjs --ledger-only
	cd server && $(CARGO) deny --all-features --locked --config ../deny.toml check advisories bans licenses sources
