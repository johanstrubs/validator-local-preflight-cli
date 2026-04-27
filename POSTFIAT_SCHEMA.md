# `.well-known/postfiat.toml` Schema

The CLI checks the attestation file at:

`https://<your-domain>/.well-known/postfiat.toml`

Minimal supported structure:

```toml
[[VALIDATORS]]
public_key = "nHYourValidatorPublicKey"
network = "testnet"
```

Accepted fields:

- `public_key`: required for CLI validation
- `network`: optional but recommended; should match `testnet` or `mainnet`

Notes:

- Multiple `[[VALIDATORS]]` entries are allowed.
- The CLI treats a missing `network` field as advisory rather than fatal.
- The CLI compares `public_key` against `server_info.pubkey_validator`.
