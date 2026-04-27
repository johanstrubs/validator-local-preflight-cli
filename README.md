# Validator Local Preflight CLI

Open-source Python CLI for local validator onboarding checks. It emits machine-readable JSON to stdout and a human-readable summary to stderr so operators can catch RPC, peer, version, ledger, attestation, and optional Docker issues before relying on dashboard access.

## Install from source

```bash
git clone <repo-url>
cd validator-local-preflight-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

Default local RPC endpoint (`http://127.0.0.1:5005`):

```bash
validator-preflight
```

Explicit endpoint:

```bash
validator-preflight http://127.0.0.1:5005
```

Domain attestation checks:

```bash
validator-preflight http://127.0.0.1:5005 --domain validator.example.com
```

Extended checks:

```bash
validator-preflight http://127.0.0.1:5005 --full
```

JSON only:

```bash
validator-preflight --json-only
```

Optional upload:

```bash
validator-preflight --upload-url https://example.com/preflight-reports
```

## What it checks

Core:

- `server_info` reachability with timeout
- server state (`proposing` or `full`)
- build version comparison against the public upgrades API
- validated ledger age under 10 seconds
- peer count of at least 5
- local peer port `2559` listening
- best-effort firewall findings

Optional `--domain`:

- DNS resolution
- TLS validity and 30-day expiry warning
- `/.well-known/postfiat.toml` fetch
- attestation `public_key` and `network` validation

Optional `--full`:

- `/crawl` `pubkey_validator` cross-check
- Docker container status and restart policy
- at least 10 GB free disk

## Output contract

- JSON goes to `stdout`
- color summary goes to `stderr`
- every check returns:
  - `status`: `pass`, `warn`, `fail`, or `skip`
  - `detected_value`
  - `expected_value`
  - `remediation`

Upload behavior:

- `--upload-url` is optional
- the CLI performs an HTTPS POST with a 10 second timeout
- upload failures never fail the entire run
- upload is reported as its own `upload` check with `pass`, `warn`, or `skip`

## `.well-known/postfiat.toml`

See [POSTFIAT_SCHEMA.md](POSTFIAT_SCHEMA.md) for the documented schema the CLI validates.

## Example reports

- [examples/passing-report.json](examples/passing-report.json)
- [examples/failing-report.json](examples/failing-report.json)

## Real-run artifact

- [artifacts/real-run-terminal-output.txt](artifacts/real-run-terminal-output.txt)

This repository includes a captured terminal artifact from running the CLI against an authorized validator environment.
