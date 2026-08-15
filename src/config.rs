//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.azure-identity`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureConfig {
    /// Entra v2 authority host. Default
    /// `https://login.microsoftonline.com`. Override for sovereign
    /// clouds or tests. `https://` (or `http://localhost` for tests).
    #[serde(default = "default_authority_host")]
    pub authority_host: String,

    /// IMDS / App-Service token endpoint override (managed_identity
    /// only). `None` → `http://169.254.169.254/metadata/identity/oauth2/token`.
    /// Set to a mock base for tests.
    #[serde(default)]
    pub imds_endpoint: Option<String>,

    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_operation_timeout_ms")]
    pub operation_timeout_ms: u64,

    /// Per-target mapping. At least one target required.
    pub targets: BTreeMap<String, TargetConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum BaseAuth {
    /// AKS Azure AD Workload Identity / federated credential. Reads the
    /// projected JWT from `federated_token_file` (or, when unset,
    /// `AZURE_FEDERATED_TOKEN_FILE`) and forwards it as the
    /// client_assertion. No local signing.
    WorkloadIdentity {
        /// Override for `AZURE_FEDERATED_TOKEN_FILE`. Config-origin
        /// only — never identity-derived.
        #[serde(default)]
        federated_token_file: Option<String>,
    },
    /// Non-federated app secret. Supply via `${env.X}` / `cred://`.
    ClientSecret { client_secret: String },
    /// IMDS managed identity (system- or user-assigned via target
    /// `client_id`).
    ManagedIdentity {},
    /// Operator-supplied token (tests / trivial setups).
    StaticToken {
        token: String,
        #[serde(default = "default_static_ttl")]
        expires_in_seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMapping {
    /// Always use the operator-fixed `scope`/`resource`. Default.
    #[default]
    Static,
    /// Derive the scope from `${identity.<field>}` (v2 modes only).
    ScopeTemplate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Entra tenant id (GUID or verified domain). Required for v2 modes
    /// (workload_identity, client_secret). Ignored by managed_identity
    /// / static_token.
    #[serde(default)]
    pub tenant_id: String,

    /// App-registration / managed-identity client id. Required for v2
    /// modes; optional for managed_identity (selects a UAMI); ignored
    /// by static_token.
    #[serde(default)]
    pub client_id: String,

    /// v2 scope, e.g. `https://storage.azure.com/.default`. Required
    /// for v2 modes with `identity_mapping=static`.
    #[serde(default)]
    pub scope: String,

    /// v1 IMDS resource, e.g. `https://storage.azure.com`. Required for
    /// managed_identity.
    #[serde(default)]
    pub resource: String,

    /// How the gateway authenticates to Entra for THIS target.
    pub base_auth: BaseAuth,

    /// `static` (default) | `scope_template`.
    #[serde(default)]
    pub identity_mapping: IdentityMapping,

    /// Required when `identity_mapping=scope_template`. `${identity.<field>}`
    /// → an https scope URL. v2 modes only.
    #[serde(default)]
    pub scope_template: Option<String>,

    /// Optional allowlist of scopes/resources this target may request.
    /// Bounds identity-derived scopes.
    #[serde(default)]
    pub allowed_scopes: Option<Vec<String>>,

    /// Cap on the host cache TTL (ms). `1..=86_400_000`. Default
    /// 3_600_000.
    #[serde(default = "default_max_cache_ttl_ms")]
    pub max_cache_ttl_ms: u64,
}

impl BaseAuth {
    /// v2 token-endpoint modes use `scope`; IMDS uses `resource`.
    fn is_v2(&self) -> bool {
        matches!(
            self,
            BaseAuth::WorkloadIdentity { .. } | BaseAuth::ClientSecret { .. }
        )
    }
}

fn default_authority_host() -> String {
    "https://login.microsoftonline.com".into()
}
fn default_connect_timeout_ms() -> u64 {
    5000
}
fn default_operation_timeout_ms() -> u64 {
    10_000
}
fn default_static_ttl() -> u64 {
    3600
}
fn default_max_cache_ttl_ms() -> u64 {
    3_600_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.azure-identity config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.azure-identity: {field} must be https:// (or http://localhost for tests)")]
    InvalidEndpointScheme { field: &'static str },
    #[error("credential.azure-identity: targets must be non-empty")]
    EmptyTargets,
    #[error("credential.azure-identity: target `{name}` requires a non-empty tenant_id")]
    MissingTenantId { name: String },
    #[error("credential.azure-identity: target `{name}` tenant_id contains an invalid character")]
    InvalidTenantId { name: String },
    #[error("credential.azure-identity: target `{name}` requires a non-empty client_id")]
    MissingClientId { name: String },
    #[error("credential.azure-identity: target `{name}` client_secret is empty")]
    EmptyClientSecret { name: String },
    #[error(
        "credential.azure-identity: target `{name}` requires a valid https scope (static v2 mode)"
    )]
    MissingScope { name: String },
    #[error("credential.azure-identity: target `{name}` scope `{scope}` is not a valid https URL")]
    InvalidScope { name: String, scope: String },
    #[error(
        "credential.azure-identity: target `{name}` requires a valid https resource (managed_identity)"
    )]
    MissingResource { name: String },
    #[error(
        "credential.azure-identity: target `{name}` resource `{resource}` is not a valid https URL"
    )]
    InvalidResource { name: String, resource: String },
    #[error(
        "credential.azure-identity: target `{name}` scope_template is required for identity_mapping=scope_template"
    )]
    TemplateTargetMissingTemplate { name: String },
    #[error(
        "credential.azure-identity: target `{name}` scope_template is only valid for v2 base-auth modes (workload_identity / client_secret)"
    )]
    TemplateNotSupportedForMode { name: String },
    #[error(
        "credential.azure-identity: target `{name}` allowed_scopes entry `{scope}` is not a valid https URL"
    )]
    InvalidAllowedScope { name: String, scope: String },
    #[error("credential.azure-identity: target `{name}` static_token.token is empty")]
    EmptyStaticToken { name: String },
    #[error(
        "credential.azure-identity: target `{name}` max_cache_ttl_ms={ttl}; must be 1..=86_400_000"
    )]
    InvalidMaxCacheTtl { name: String, ttl: u64 },
}

/// An endpoint override is config-origin; constrain it to `https://`
/// anywhere or `http://` to an exact localhost host (test carve-out).
pub(crate) fn is_allowed_endpoint(url: &str) -> bool {
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty();
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        return matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    }
    false
}

/// A tenant id is a GUID or a verified-domain string; it lands in the
/// `…/{tenant}/oauth2/v2.0/token` URL path, so reject path-breakout
/// bytes (`/ : ? # %` whitespace) — only `[A-Za-z0-9.-]`.
pub(crate) fn is_valid_tenant_id(tenant: &str) -> bool {
    !tenant.is_empty()
        && tenant.len() <= 256
        && tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

impl AzureConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !is_allowed_endpoint(&self.authority_host) {
            return Err(ConfigError::InvalidEndpointScheme {
                field: "authority_host",
            });
        }
        if let Some(ep) = &self.imds_endpoint
            && !is_allowed_endpoint(ep)
        {
            return Err(ConfigError::InvalidEndpointScheme {
                field: "imds_endpoint",
            });
        }
        if self.targets.is_empty() {
            return Err(ConfigError::EmptyTargets);
        }
        for (name, target) in &self.targets {
            self.validate_target(name, target)?;
        }
        Ok(())
    }

    fn validate_target(&self, name: &str, t: &TargetConfig) -> Result<(), ConfigError> {
        use crate::identity_mapping::is_valid_scope;

        let template_mode = t.identity_mapping == IdentityMapping::ScopeTemplate;

        match &t.base_auth {
            BaseAuth::WorkloadIdentity { .. } | BaseAuth::ClientSecret { .. } => {
                if t.tenant_id.is_empty() {
                    return Err(ConfigError::MissingTenantId { name: name.into() });
                }
                if !is_valid_tenant_id(&t.tenant_id) {
                    return Err(ConfigError::InvalidTenantId { name: name.into() });
                }
                if t.client_id.is_empty() {
                    return Err(ConfigError::MissingClientId { name: name.into() });
                }
                if let BaseAuth::ClientSecret { client_secret } = &t.base_auth
                    && client_secret.is_empty()
                {
                    return Err(ConfigError::EmptyClientSecret { name: name.into() });
                }
                // Static mapping needs a valid operator scope; template
                // mode derives it at issue time.
                if !template_mode {
                    if t.scope.is_empty() {
                        return Err(ConfigError::MissingScope { name: name.into() });
                    }
                    if !is_valid_scope(&t.scope) {
                        return Err(ConfigError::InvalidScope {
                            name: name.into(),
                            scope: t.scope.clone(),
                        });
                    }
                }
            }
            BaseAuth::ManagedIdentity {} => {
                if template_mode {
                    return Err(ConfigError::TemplateNotSupportedForMode { name: name.into() });
                }
                if t.resource.is_empty() {
                    return Err(ConfigError::MissingResource { name: name.into() });
                }
                if !is_valid_scope(&t.resource) {
                    return Err(ConfigError::InvalidResource {
                        name: name.into(),
                        resource: t.resource.clone(),
                    });
                }
            }
            BaseAuth::StaticToken { token, .. } => {
                if template_mode {
                    return Err(ConfigError::TemplateNotSupportedForMode { name: name.into() });
                }
                if token.is_empty() {
                    return Err(ConfigError::EmptyStaticToken { name: name.into() });
                }
            }
        }

        if template_mode {
            if !t.base_auth.is_v2() {
                return Err(ConfigError::TemplateNotSupportedForMode { name: name.into() });
            }
            if t.scope_template
                .as_deref()
                .map(str::is_empty)
                .unwrap_or(true)
            {
                return Err(ConfigError::TemplateTargetMissingTemplate { name: name.into() });
            }
        }

        if let Some(allow) = &t.allowed_scopes {
            for scope in allow {
                if !is_valid_scope(scope) {
                    return Err(ConfigError::InvalidAllowedScope {
                        name: name.into(),
                        scope: scope.clone(),
                    });
                }
            }
        }

        if t.max_cache_ttl_ms == 0 || t.max_cache_ttl_ms > 86_400_000 {
            return Err(ConfigError::InvalidMaxCacheTtl {
                name: name.into(),
                ttl: t.max_cache_ttl_ms,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn client_secret_target() -> serde_json::Value {
        json!({
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "scope": "https://storage.azure.com/.default",
            "base_auth": { "mode": "client_secret", "client_secret": "s3cr3t" }
        })
    }

    fn minimal() -> serde_json::Value {
        json!({ "targets": { "storage": client_secret_target() } })
    }

    #[test]
    fn parses_minimal_client_secret() {
        let cfg = AzureConfig::parse(&minimal().to_string()).unwrap();
        assert_eq!(cfg.authority_host, "https://login.microsoftonline.com");
        let t = &cfg.targets["storage"];
        assert_eq!(t.identity_mapping, IdentityMapping::Static);
        assert_eq!(t.max_cache_ttl_ms, 3_600_000);
    }

    #[test]
    fn rejects_unknown_field() {
        let mut v = minimal();
        v["bogus"] = json!(1);
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidJson(_)
        ));
    }

    #[test]
    fn rejects_empty_targets() {
        let v = json!({ "targets": {} });
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyTargets
        ));
    }

    #[test]
    fn rejects_bad_authority_scheme() {
        let mut v = minimal();
        v["authority_host"] = json!("ftp://login");
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidEndpointScheme { .. }
        ));
    }

    #[test]
    fn client_secret_requires_tenant_and_client_id() {
        let mut v = minimal();
        v["targets"]["storage"]["tenant_id"] = json!("");
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::MissingTenantId { .. }
        ));
        let mut v2 = minimal();
        v2["targets"]["storage"]["client_id"] = json!("");
        assert!(matches!(
            AzureConfig::parse(&v2.to_string()).unwrap_err(),
            ConfigError::MissingClientId { .. }
        ));
    }

    #[test]
    fn rejects_tenant_with_path_breakout() {
        let mut v = minimal();
        v["targets"]["storage"]["tenant_id"] = json!("tenant/../../evil");
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidTenantId { .. }
        ));
    }

    #[test]
    fn client_secret_static_requires_valid_scope() {
        let mut v = minimal();
        v["targets"]["storage"]["scope"] = json!("");
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::MissingScope { .. }
        ));
        let mut v2 = minimal();
        v2["targets"]["storage"]["scope"] = json!("http://storage.azure.com/.default");
        assert!(matches!(
            AzureConfig::parse(&v2.to_string()).unwrap_err(),
            ConfigError::InvalidScope { .. }
        ));
    }

    #[test]
    fn empty_client_secret_rejected() {
        let mut v = minimal();
        v["targets"]["storage"]["base_auth"] =
            json!({ "mode": "client_secret", "client_secret": "" });
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyClientSecret { .. }
        ));
    }

    #[test]
    fn managed_identity_requires_resource() {
        let v = json!({
            "targets": { "mi": { "base_auth": { "mode": "managed_identity" } } }
        });
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::MissingResource { .. }
        ));
    }

    #[test]
    fn managed_identity_resource_roundtrip() {
        let v = json!({
            "imds_endpoint": "http://localhost:4599",
            "targets": { "mi": { "resource": "https://storage.azure.com", "base_auth": { "mode": "managed_identity" } } }
        });
        assert!(AzureConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn scope_template_requires_template_and_is_v2_only() {
        let mut v = minimal();
        v["targets"]["storage"]["identity_mapping"] = json!("scope_template");
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::TemplateTargetMissingTemplate { .. }
        ));
        // managed_identity + scope_template → rejected
        let v2 = json!({
            "targets": { "mi": {
                "resource": "https://storage.azure.com",
                "base_auth": { "mode": "managed_identity" },
                "identity_mapping": "scope_template",
                "scope_template": "https://x/.default"
            } }
        });
        assert!(matches!(
            AzureConfig::parse(&v2.to_string()).unwrap_err(),
            ConfigError::TemplateNotSupportedForMode { .. }
        ));
    }

    #[test]
    fn scope_template_v2_ok() {
        let mut v = minimal();
        v["targets"]["storage"]["identity_mapping"] = json!("scope_template");
        v["targets"]["storage"]["scope_template"] =
            json!("https://${identity.attributes.resource}/.default");
        v["targets"]["storage"]["scope"] = json!("");
        assert!(AzureConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_bad_allowlist_entry() {
        let mut v = minimal();
        v["targets"]["storage"]["allowed_scopes"] = json!(["https://ok/.default", "not a url"]);
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidAllowedScope { .. }
        ));
    }

    #[test]
    fn rejects_zero_ttl() {
        let mut v = minimal();
        v["targets"]["storage"]["max_cache_ttl_ms"] = json!(0);
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidMaxCacheTtl { .. }
        ));
    }

    #[test]
    fn static_token_requires_token() {
        let v = json!({
            "targets": { "st": { "base_auth": { "mode": "static_token", "token": "" } } }
        });
        assert!(matches!(
            AzureConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyStaticToken { .. }
        ));
    }

    #[test]
    fn workload_identity_roundtrip() {
        let v = json!({
            "targets": { "wi": {
                "tenant_id": "contoso.onmicrosoft.com",
                "client_id": "33333333-3333-3333-3333-333333333333",
                "scope": "https://graph.microsoft.com/.default",
                "base_auth": { "mode": "workload_identity", "federated_token_file": "/var/run/x" }
            } }
        });
        let cfg = AzureConfig::parse(&v.to_string()).unwrap();
        match &cfg.targets["wi"].base_auth {
            BaseAuth::WorkloadIdentity {
                federated_token_file,
            } => {
                assert_eq!(federated_token_file.as_deref(), Some("/var/run/x"));
            }
            other => panic!("{other:?}"),
        }
    }
}
