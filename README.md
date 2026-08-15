# Azure Entra Workload-Identity Credentials (`dev.mcpg.credential.azure-identity`)

A **credential_issuer** plugin that issues **Azure AD (Entra) bearer
tokens for a downstream resource** per caller request. The gateway
proves its **own** workload identity to Entra — via federated workload
identity (AKS), a managed identity (IMDS), or a client secret — and
receives a token scoped to the target resource. Bindings consume it via
the `cred://` scheme (`Authorization: Bearer ${cred://azure/<target>}`).

## How identity maps (and what's out of scope)

Azure targets are largely **operator-fixed**: a named target is a
`{ scope/resource, tenant, client_id, base-auth }`. Identity steers only
the requested **scope** (`scope_template`), not the issuing identity.

**On-Behalf-Of is out of scope.** Per-caller *distinct* Azure identities
(OBO) require the caller's raw inbound token, which a `credential_issuer`
never receives — the gateway parses and discards it. This plugin issues
the gateway-workload-identity's token for a target resource, with
identity-gated scope selection.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `authority_host` | string | `https://login.microsoftonline.com` | Entra v2 authority. `https://` (or `http://localhost` for tests). Set for sovereign clouds. |
| `imds_endpoint` | string | *(IMDS default)* | Managed-identity token endpoint override (tests). |
| `connect_timeout_ms` / `operation_timeout_ms` | int | `5000` / `10000` | HTTP timeouts. |
| `targets` | map | *(required, ≥1)* | Per-target mapping (below). |

### Target

| Field | Type | Default | Description |
|---|---|---|---|
| `base_auth` | object | *(required)* | How the gateway authenticates to Entra (below). |
| `tenant_id` | string | `""` | Entra tenant (GUID/domain). Required for v2 modes. |
| `client_id` | string | `""` | App / managed-identity client id. Required for v2; optional UAMI selector for managed_identity. |
| `scope` | string | `""` | v2 scope, e.g. `https://storage.azure.com/.default`. Required for v2 static mapping. |
| `resource` | string | `""` | IMDS v1 resource, e.g. `https://storage.azure.com`. Required for managed_identity. |
| `identity_mapping` | `static` \| `scope_template` | `static` | `scope_template` derives the scope from identity (v2 modes only). |
| `scope_template` | string | *(none)* | Required for `scope_template`; `${identity.<field>}` → an https scope. |
| `allowed_scopes` | array | *(none)* | Allowlist bounding identity-derived scopes. |
| `max_cache_ttl_ms` | int | `3600000` | Caps the host cache TTL; effective TTL is `min(token_expiry, this)`. |

### `base_auth`

- `{ "mode": "workload_identity", "federated_token_file"? }` — AKS Azure
  AD Workload Identity. Reads the projected JWT from
  `federated_token_file` (or, when unset, `AZURE_FEDERATED_TOKEN_FILE`)
  and forwards it as the client-assertion. **No local signing.** The
  path is config-origin, never identity-derived.
- `{ "mode": "client_secret", "client_secret": "${env.AZURE_CLIENT_SECRET}" }`.
- `{ "mode": "managed_identity" }` — IMDS (uses `resource`).
- `{ "mode": "static_token", "token": "...", "expires_in_seconds"? }` —
  tests / trivial setups; no network.

### Security floor

`static` uses the operator-fixed scope/resource. `scope_template` derives
the scope from the caller. **Any identity-derived scope is honoured only
for a Verified principal** — header-asserted / unauthenticated callers
are refused (`NotAuthorized`). The resolved value must be a well-formed
`https://` URL (no userinfo / injection — it flows into the `scope`
form param) and, if `allowed_scopes` is set, appear in it. Operator-fixed
values are exempt. `tenant_id` (in the token URL path) is restricted to
`[A-Za-z0-9.-]` (no path-breakout).

## Example

```yaml
# Top-level `plugins:` is a flat list of plugin entries.
plugins:
  - id: dev.mcpg.credential.azure-identity
    class: credential_issuer
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/credential-azure-identity:protocol-1" }
    config:
      targets:
        graph:
          base_auth: { mode: workload_identity }   # reads AZURE_FEDERATED_TOKEN_FILE
          tenant_id: "contoso.onmicrosoft.com"
          client_id: "00000000-0000-0000-0000-000000000000"
          scope: "https://graph.microsoft.com/.default"
        storage:
          base_auth: { mode: managed_identity }
          resource: "https://storage.azure.com"
```

Bindings consume the issued token via `cred://azure-identity/<target>` in any
config-origin position.

## Issued credential

`value` + `parts.access_token` (+ `parts.token_type`) hold the token;
`ttl_seconds` is the token's remaining lifetime (Entra `expires_in` /
IMDS `expires_on`) capped at `max_cache_ttl_ms`. `lease_id` is absent —
Entra `client_credentials` tokens auto-expire; `revoke` is a no-op.

## Testing

Unit tests (`cargo test -p mcpg-plugin-credential-azure-identity --lib`)
cover config validation, scope resolution + the Verified / https-shape /
allowlist guards, and error mapping — all offline. The HTTP
request/response contract (Entra v2 token endpoint + IMDS) is exercised
offline with [`wiremock`] in the same `--lib` run (no Docker), including
reading a federated token from a temp file. A **live Azure integration**
run is deferred to a later orchestrated test pass.

## Notes

- Pure-Rust, rustls-only (`reqwest` `rustls-tls`, no `azure_identity`
  SDK — workload identity forwards the projected token, no signing).
- `network_outbound` capability.
- The authority / IMDS hosts are config-origin (operator-fixed); only
  the *scope* is identity-derived. Errors surface the Entra `error` code
  only — never `error_description` (which can echo AADSTS material).

[`wiremock`]: https://docs.rs/wiremock
