//! `dev.mcpg.credential.azure-identity` — `credential_issuer` plugin.
//!
//! Issues Azure AD (Entra) bearer tokens for a downstream resource per
//! caller request. The gateway proves its **own** workload identity to
//! Entra — via federated workload identity (AKS), a managed identity
//! (IMDS), or a client secret — and receives a token scoped to the
//! target resource. Mirrors `libs/plugins/credential/vault-dynamic-db`
//! (reqwest + bundled runtime) and reuses the Verified-trust gate +
//! allowlist pattern from `libs/plugins/credential/aws-sts`.
//!
//! # Scope
//!
//! - **Base auth**: `workload_identity` (federated client-assertion,
//!   no local signing), `managed_identity` (IMDS), `client_secret`,
//!   `static_token`.
//! - **Identity mapping**: `static` (operator-fixed scope/resource) or
//!   `scope_template` (derive the scope from identity, v2 modes only) —
//!   identity-derived scopes require Verified trust + an https-URL shape
//!   check + an optional per-target allowlist.
//! - **No revocation**: Entra `client_credentials` tokens auto-expire;
//!   `revoke` is a no-op.
//!
//! # Out of scope
//!
//! Per-caller **distinct** Azure identities (On-Behalf-Of) require the
//! caller's raw inbound token, which a `credential_issuer` never
//! receives (the gateway parses + discards it). OBO is therefore not
//! implementable here; identity steers only the requested **scope**,
//! not the issuing identity.

mod client;
mod config;
mod identity_mapping;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use tokio::runtime::Runtime;

use client::V2Auth;
pub use config::{AzureConfig, BaseAuth, ConfigError, IdentityMapping, TargetConfig};

const PLUGIN_ID: &str = "dev.mcpg.credential.azure-identity";

pub struct AzureIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: AzureConfig,
    client: client::EntraClient,
    sync_runtime: OnceLock<Runtime>,
}

impl AzureIdentityPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = AzureConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "azure-identity: config parse failed; refusing to register"
            );
            panic!(
                "azure-identity config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: AzureConfig) -> Self {
        let client = client::EntraClient::new(&cfg)
            .unwrap_or_else(|err| panic!("azure-identity: HTTP client init failed: {err}"));
        tracing::info!(
            plugin_id = PLUGIN_ID,
            authority = %cfg.authority_host,
            target_count = cfg.targets.len(),
            "azure-identity: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "Azure Entra Workload-Identity Credentials".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                client,
                sync_runtime: OnceLock::new(),
            }),
        }
    }
}

async fn issue_inner(
    inner: &Inner,
    identity: &PluginIdentity,
    target_name: &str,
) -> Result<IssuedCredential, CredentialError> {
    let target =
        inner
            .config
            .targets
            .get(target_name)
            .ok_or_else(|| CredentialError::Misconfigured {
                reason: format!("unknown target: {target_name}"),
            })?;

    // static_token short-circuits: no scope resolution, no network.
    if let BaseAuth::StaticToken {
        token,
        expires_in_seconds,
    } = &target.base_auth
    {
        metric_issue(target_name, "ok");
        let ttl = cap_ttl_seconds(*expires_in_seconds, target.max_cache_ttl_ms);
        return Ok(build_credential(
            target,
            token.clone(),
            "Bearer".into(),
            String::new(),
            ttl,
        ));
    }

    // Resolve the scope (v2 modes) or use the operator-fixed resource
    // (managed_identity — config forces static mapping there).
    let (value, identity_derived) = match &target.base_auth {
        BaseAuth::ManagedIdentity {} => (target.resource.clone(), false),
        _ => match identity_mapping::resolve_scope(identity, target) {
            identity_mapping::Resolution::Scope {
                value,
                identity_derived,
            } => (value, identity_derived),
            identity_mapping::Resolution::EmptyDerived { reason } => {
                metric_issue(target_name, "empty_identity");
                return Err(CredentialError::NotAuthorized { reason });
            }
            identity_mapping::Resolution::SubstitutionFailed { field } => {
                metric_issue(target_name, "substitution_failed");
                return Err(CredentialError::NotAuthorized {
                    reason: format!(
                        "scope template substitution failed: field `{field}` is None or out-of-bounds"
                    ),
                });
            }
        },
    };

    // A scope/resource derived from caller-controlled identity must come
    // from a Verified principal — audience selection is privilege
    // selection. Operator-fixed values are exempt.
    if identity_derived && identity.trust_level != "verified" {
        metric_issue(target_name, "untrusted_identity");
        return Err(CredentialError::NotAuthorized {
            reason: format!(
                "identity-derived scope requires Verified trust; caller trust is `{}`",
                identity.trust_level
            ),
        });
    }
    // The value flows into the `scope`/`resource` form param; reject
    // anything that isn't a clean https URL (SSRF / form injection).
    if !identity_mapping::is_valid_scope(&value) {
        metric_issue(target_name, "invalid_scope");
        return Err(CredentialError::NotAuthorized {
            reason: "resolved value is not a valid https scope/resource".into(),
        });
    }
    if let Some(allow) = &target.allowed_scopes
        && !allow.iter().any(|a| a == &value)
    {
        metric_issue(target_name, "scope_not_allowed");
        return Err(CredentialError::NotAuthorized {
            reason: "resolved scope is not in this target's allowed_scopes".into(),
        });
    }

    let started = std::time::Instant::now();
    let issued = match &target.base_auth {
        BaseAuth::ClientSecret { client_secret } => {
            inner
                .client
                .fetch_v2_token(
                    &target.tenant_id,
                    &target.client_id,
                    &value,
                    V2Auth::ClientSecret(client_secret.clone()),
                )
                .await?
        }
        BaseAuth::WorkloadIdentity {
            federated_token_file,
        } => {
            let assertion = client::read_federated_token(federated_token_file)?;
            inner
                .client
                .fetch_v2_token(
                    &target.tenant_id,
                    &target.client_id,
                    &value,
                    V2Auth::Assertion(assertion),
                )
                .await?
        }
        BaseAuth::ManagedIdentity {} => {
            let cid = (!target.client_id.is_empty()).then_some(target.client_id.as_str());
            inner.client.fetch_imds_token(&value, cid).await?
        }
        BaseAuth::StaticToken { .. } => unreachable!("static_token handled above"),
    };
    metrics::histogram!(
        "mcpg_azure_identity_issue_latency_ms",
        "target" => target_name.to_owned(),
    )
    .record(started.elapsed().as_millis() as f64);
    metric_issue(target_name, "ok");

    let ttl = cap_ttl_seconds(issued.ttl_seconds, target.max_cache_ttl_ms);
    Ok(build_credential(
        target,
        issued.token,
        issued.token_type,
        value,
        ttl,
    ))
}

fn build_credential(
    target: &TargetConfig,
    token: String,
    token_type: String,
    scope: String,
    ttl_seconds: u64,
) -> IssuedCredential {
    let mut parts = BTreeMap::new();
    parts.insert("access_token".to_string(), token.clone());
    parts.insert("token_type".to_string(), token_type.clone());

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "azure.base_auth".to_string(),
        base_auth_label(&target.base_auth).to_string(),
    );
    metadata.insert("azure.token_type".to_string(), token_type);
    if !scope.is_empty() {
        metadata.insert("azure.scope".to_string(), scope);
    }
    if !target.tenant_id.is_empty() {
        metadata.insert("azure.tenant_id".to_string(), target.tenant_id.clone());
    }
    if !target.client_id.is_empty() {
        metadata.insert("azure.client_id".to_string(), target.client_id.clone());
    }

    IssuedCredential {
        value: Some(token),
        parts,
        ttl_seconds,
        // Entra client_credentials tokens have no revocation primitive.
        lease_id: None,
        issued_at: now_rfc3339(),
        metadata,
    }
}

fn base_auth_label(b: &BaseAuth) -> &'static str {
    match b {
        BaseAuth::WorkloadIdentity { .. } => "workload_identity",
        BaseAuth::ClientSecret { .. } => "client_secret",
        BaseAuth::ManagedIdentity {} => "managed_identity",
        BaseAuth::StaticToken { .. } => "static_token",
    }
}

fn metric_issue(target: &str, result: &str) {
    metrics::counter!(
        "mcpg_azure_identity_issue_total",
        "target" => target.to_owned(),
        "result" => result.to_owned(),
    )
    .increment(1);
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn cap_ttl_seconds(token_ttl_secs: u64, max_cache_ttl_ms: u64) -> u64 {
    (max_cache_ttl_ms / 1000).max(1).min(token_ttl_secs)
}

#[async_trait]
impl CredentialIssuer for AzureIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, identity, target).await
    }

    // Entra client_credentials tokens auto-expire; no revocation.
}

impl SyncCredentialIssuer for AzureIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let runtime = self.inner.sync_runtime.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("azure-identity: failed to build tokio runtime")
        });
        let inner = Arc::clone(&self.inner);
        let identity = identity.clone();
        let target = target.to_owned();
        runtime.block_on(async move { issue_inner(&inner, &identity, &target).await })
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: AzureIdentityPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> AzureIdentityPlugin {
                AzureIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cap(secs: u64, ms: u64) -> u64 {
        cap_ttl_seconds(secs, ms)
    }

    #[test]
    fn cap_ttl_clamps_and_floors() {
        assert_eq!(cap(3600, 60_000), 60);
        assert_eq!(cap(45, 3_600_000), 45);
        assert_eq!(cap(3600, 500), 1);
    }

    fn identity(trust: &str, subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: trust.into(),
            trust_level: trust.into(),
            subject_id: Some(subject.into()),
            auth_provider: Some("entra".into()),
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    fn scope_template_plugin(allowed: Option<Vec<&str>>) -> AzureIdentityPlugin {
        let mut target = json!({
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "base_auth": { "mode": "client_secret", "client_secret": "s3cr3t" },
            "identity_mapping": "scope_template",
            "scope_template": "${identity.subject_id}"
        });
        if let Some(a) = allowed {
            target["allowed_scopes"] = json!(a);
        }
        let cfg = json!({ "targets": { "t": target } });
        AzureIdentityPlugin::from_config_json(&cfg.to_string())
    }

    // ---- construction ----

    #[test]
    fn from_config_json_succeeds() {
        let p = scope_template_plugin(None);
        assert_eq!(p.inner.manifest.id, PLUGIN_ID);
        assert_eq!(p.inner.manifest.plugin_class, PluginClass::CredentialIssuer);
    }

    #[test]
    #[should_panic(expected = "azure-identity config parse failed")]
    fn malformed_config_panics() {
        AzureIdentityPlugin::from_config_json("{ not json");
    }

    #[test]
    #[should_panic(expected = "azure-identity config parse failed")]
    fn empty_targets_panics() {
        AzureIdentityPlugin::from_config_json(&json!({ "targets": {} }).to_string());
    }

    // ---- identity-derived scope guards (return before any HTTP) ----

    #[test]
    fn issue_rejects_identity_derived_scope_from_unverified_caller() {
        let p = scope_template_plugin(None);
        let err = SyncCredentialIssuer::issue(
            &p,
            &identity("header_asserted", "https://storage.azure.com/.default"),
            "t",
            &Value::Null,
        )
        .expect_err("unverified identity-derived scope must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("Verified trust")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_malformed_scope() {
        let p = scope_template_plugin(None);
        let err = SyncCredentialIssuer::issue(
            &p,
            &identity("verified", "http://evil.example.com/.default"),
            "t",
            &Value::Null,
        )
        .expect_err("a non-https scope must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("https scope")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_scope_outside_allowlist() {
        let p = scope_template_plugin(Some(vec!["https://only.azure.com/.default"]));
        let err = SyncCredentialIssuer::issue(
            &p,
            &identity("verified", "https://other.azure.com/.default"),
            "t",
            &Value::Null,
        )
        .expect_err("scope outside allowlist must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("allowed_scopes")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_unknown_target() {
        let p = scope_template_plugin(None);
        let err = SyncCredentialIssuer::issue(&p, &identity("verified", "x"), "nope", &Value::Null)
            .expect_err("unknown target must be refused");
        assert!(
            matches!(err, CredentialError::Misconfigured { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn revoke_is_noop_ok() {
        let p = scope_template_plugin(None);
        assert!(SyncCredentialIssuer::revoke(&p, "any").is_ok());
    }

    #[test]
    fn static_token_issue_returns_token_offline() {
        let cfg = json!({
            "targets": { "st": { "base_auth": { "mode": "static_token", "token": "static-bearer", "expires_in_seconds": 1200 } } }
        });
        let p = AzureIdentityPlugin::from_config_json(&cfg.to_string());
        let cred = SyncCredentialIssuer::issue(&p, &identity("verified", "x"), "st", &Value::Null)
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("static-bearer"));
        assert_eq!(cred.ttl_seconds, 1200);
        assert_eq!(
            cred.metadata.get("azure.base_auth").map(String::as_str),
            Some("static_token")
        );
    }

    // ---- wiremock: real Entra v2 / IMDS request/response ----

    #[tokio::test]
    async fn client_secret_issue_hits_token_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("scope=https%3A%2F%2Fstorage.azure.com%2F.default"))
            .and(body_string_contains("client_secret=s3cr3t"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token_type": "Bearer", "access_token": "entra.tok", "expires_in": 3599, "ext_expires_in": 3599
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cfg = json!({
            "authority_host": server.uri(),
            "targets": { "t": {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "client_id": "22222222-2222-2222-2222-222222222222",
                "scope": "https://storage.azure.com/.default",
                "base_auth": { "mode": "client_secret", "client_secret": "s3cr3t" }
            } }
        });
        let p = AzureIdentityPlugin::from_config_json(&cfg.to_string());
        let cred = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("entra.tok"));
        assert_eq!(
            cred.parts.get("token_type").map(String::as_str),
            Some("Bearer")
        );
        assert!(cred.lease_id.is_none());
        assert!(
            (3590..=3599).contains(&cred.ttl_seconds),
            "{}",
            cred.ttl_seconds
        );
        assert_eq!(
            cred.metadata.get("azure.scope").map(String::as_str),
            Some("https://storage.azure.com/.default")
        );
    }

    #[tokio::test]
    async fn workload_identity_reads_token_file_and_sends_assertion() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/contoso.onmicrosoft.com/oauth2/v2.0/token"))
            .and(body_string_contains(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
            ))
            .and(body_string_contains("client_assertion=eyJ.fake.federated"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token_type": "Bearer", "access_token": "wi.tok", "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "eyJ.fake.federated\n").unwrap();
        let cfg = json!({
            "authority_host": server.uri(),
            "targets": { "t": {
                "tenant_id": "contoso.onmicrosoft.com",
                "client_id": "33333333-3333-3333-3333-333333333333",
                "scope": "https://graph.microsoft.com/.default",
                "base_auth": { "mode": "workload_identity", "federated_token_file": tmp.path().to_string_lossy() }
            } }
        });
        let p = AzureIdentityPlugin::from_config_json(&cfg.to_string());
        let cred = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("wi.tok"));
    }

    #[tokio::test]
    async fn entra_error_maps_not_authorized_and_redacts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "invalid_client",
                "error_description": "AADSTS7000215 LEAKED_SECRET_xyz invalid"
            })))
            .mount(&server)
            .await;
        let cfg = json!({
            "authority_host": server.uri(),
            "targets": { "t": {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "client_id": "22222222-2222-2222-2222-222222222222",
                "scope": "https://storage.azure.com/.default",
                "base_auth": { "mode": "client_secret", "client_secret": "bad" }
            } }
        });
        let p = AzureIdentityPlugin::from_config_json(&cfg.to_string());
        let err = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap_err();
        let CredentialError::NotAuthorized { reason } = err else {
            panic!("expected NotAuthorized, got {err:?}");
        };
        assert!(reason.contains("invalid_client"));
        assert!(!reason.contains("LEAKED_SECRET_xyz"), "leaked: {reason}");
    }

    #[tokio::test]
    async fn entra_429_maps_throttled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let cfg = json!({
            "authority_host": server.uri(),
            "targets": { "t": {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "client_id": "22222222-2222-2222-2222-222222222222",
                "scope": "https://storage.azure.com/.default",
                "base_auth": { "mode": "client_secret", "client_secret": "s" }
            } }
        });
        let p = AzureIdentityPlugin::from_config_json(&cfg.to_string());
        let err = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialError::Throttled { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn managed_identity_uses_imds_resource_and_absolute_expiry() {
        let server = MockServer::start().await;
        let expires_on = (chrono::Utc::now().timestamp() + 3000).to_string();
        Mock::given(method("GET"))
            .and(path("/metadata/identity/oauth2/token"))
            .and(header("metadata", "true"))
            .and(query_param("resource", "https://storage.azure.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "imds.tok", "token_type": "Bearer", "expires_on": expires_on, "resource": "https://storage.azure.com"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cfg = json!({
            "imds_endpoint": format!("{}/metadata/identity/oauth2/token", server.uri()),
            "targets": { "t": {
                "resource": "https://storage.azure.com",
                "base_auth": { "mode": "managed_identity" }
            } }
        });
        let p = AzureIdentityPlugin::from_config_json(&cfg.to_string());
        let cred = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("imds.tok"));
        assert!(
            (2990..=3000).contains(&cred.ttl_seconds),
            "{}",
            cred.ttl_seconds
        );
        assert_eq!(
            cred.metadata.get("azure.base_auth").map(String::as_str),
            Some("managed_identity")
        );
    }

    #[tokio::test]
    async fn missing_expires_in_defaults_to_one_hour() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token_type": "Bearer", "access_token": "tok"
            })))
            .mount(&server)
            .await;
        let cfg = json!({
            "authority_host": server.uri(),
            "targets": { "t": {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "client_id": "22222222-2222-2222-2222-222222222222",
                "scope": "https://storage.azure.com/.default",
                "base_auth": { "mode": "client_secret", "client_secret": "s" }
            } }
        });
        let p = AzureIdentityPlugin::from_config_json(&cfg.to_string());
        let cred = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.ttl_seconds, 3600);
    }
}
