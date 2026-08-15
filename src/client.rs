//! Azure Entra (Azure AD) token client: v2 `client_credentials`
//! (client_secret / federated client-assertion) + IMDS managed
//! identity.

use std::time::Duration;

use mcpg_plugin_protocol::credential::CredentialError;
use serde::Deserialize;

use crate::config::AzureConfig;

const DEFAULT_IMDS: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub(crate) struct EntraClient {
    http: reqwest::Client,
    authority_host: String,
    imds_endpoint: String,
}

pub(crate) struct IssuedToken {
    pub token: String,
    pub token_type: String,
    pub ttl_seconds: u64,
}

/// What the gateway presents to the v2 token endpoint.
pub(crate) enum V2Auth {
    ClientSecret(String),
    /// A federated client-assertion (the projected workload-identity
    /// JWT, forwarded verbatim — no local signing).
    Assertion(String),
}

#[derive(Deserialize)]
struct EntraTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default = "default_bearer")]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct ImdsTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default = "default_bearer")]
    token_type: String,
    /// Absolute epoch seconds (string) — IMDS uses `expires_on`, not a
    /// relative `expires_in`.
    #[serde(default)]
    expires_on: String,
}

fn default_bearer() -> String {
    "Bearer".to_owned()
}

impl EntraClient {
    pub(crate) fn new(cfg: &AzureConfig) -> Result<Self, CredentialError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(cfg.connect_timeout_ms))
            .timeout(Duration::from_millis(cfg.operation_timeout_ms))
            .build()
            .map_err(|e| CredentialError::Backend {
                reason: format!("reqwest client init: {e}"),
            })?;
        Ok(Self {
            http,
            authority_host: cfg.authority_host.trim_end_matches('/').to_owned(),
            imds_endpoint: cfg
                .imds_endpoint
                .as_deref()
                .unwrap_or(DEFAULT_IMDS)
                .trim_end_matches('/')
                .to_owned(),
        })
    }

    pub(crate) async fn fetch_v2_token(
        &self,
        tenant_id: &str,
        client_id: &str,
        scope: &str,
        auth: V2Auth,
    ) -> Result<IssuedToken, CredentialError> {
        let url = format!("{}/{}/oauth2/v2.0/token", self.authority_host, tenant_id);
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("scope", scope),
        ];
        // Bind the secret/assertion to a stable slot so its &str outlives
        // the form.
        let assertion;
        match &auth {
            V2Auth::ClientSecret(secret) => {
                form.push(("client_secret", secret.as_str()));
            }
            V2Auth::Assertion(token) => {
                assertion = token.clone();
                form.push(("client_assertion_type", ASSERTION_TYPE));
                form.push(("client_assertion", assertion.as_str()));
            }
        }

        let resp = self.http.post(&url).form(&form).send().await.map_err(|e| {
            CredentialError::Backend {
                reason: format!("Entra token endpoint unreachable: {e}"),
            }
        })?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(map_entra_error(status, &body));
        }
        let parsed: EntraTokenResponse =
            resp.json().await.map_err(|e| CredentialError::Backend {
                reason: format!("parse Entra token response: {e}"),
            })?;
        if parsed.access_token.is_empty() {
            return Err(CredentialError::Backend {
                reason: "Entra token response had an empty access_token".into(),
            });
        }
        Ok(IssuedToken {
            token: parsed.access_token,
            token_type: parsed.token_type,
            ttl_seconds: parsed.expires_in.unwrap_or(3600),
        })
    }

    pub(crate) async fn fetch_imds_token(
        &self,
        resource: &str,
        client_id: Option<&str>,
    ) -> Result<IssuedToken, CredentialError> {
        let mut req = self
            .http
            .get(&self.imds_endpoint)
            .header("Metadata", "true")
            .query(&[("api-version", "2018-02-01"), ("resource", resource)]);
        if let Some(cid) = client_id.filter(|c| !c.is_empty()) {
            req = req.query(&[("client_id", cid)]);
        }
        let resp = req.send().await.map_err(|e| CredentialError::Backend {
            reason: format!("IMDS endpoint unreachable: {e}"),
        })?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(map_entra_error(status, &body));
        }
        let parsed: ImdsTokenResponse =
            resp.json().await.map_err(|e| CredentialError::Backend {
                reason: format!("parse IMDS token response: {e}"),
            })?;
        if parsed.access_token.is_empty() {
            return Err(CredentialError::Backend {
                reason: "IMDS token response had an empty access_token".into(),
            });
        }
        let ttl = parsed
            .expires_on
            .parse::<i64>()
            .ok()
            .map(|exp| (exp - chrono::Utc::now().timestamp()).max(1) as u64)
            .unwrap_or(3600);
        Ok(IssuedToken {
            token: parsed.access_token,
            token_type: parsed.token_type,
            ttl_seconds: ttl,
        })
    }
}

/// Read the projected federated assertion. The path is config-origin
/// (explicit `federated_token_file`, or the AKS-injected
/// `AZURE_FEDERATED_TOKEN_FILE`) — never identity-derived. The contents
/// are a secret and must never be logged.
pub(crate) fn read_federated_token(file: &Option<String>) -> Result<String, CredentialError> {
    let path = match file {
        Some(p) => p.clone(),
        None => std::env::var("AZURE_FEDERATED_TOKEN_FILE").map_err(|_| {
            CredentialError::Misconfigured {
                reason: "workload_identity: federated_token_file unset and \
                         AZURE_FEDERATED_TOKEN_FILE is absent"
                    .into(),
            }
        })?,
    };
    let token = std::fs::read_to_string(&path).map_err(|e| CredentialError::Backend {
        reason: format!("read federated token file `{path}`: {e}"),
    })?;
    Ok(token.trim().to_owned())
}

/// Map an Entra / IMDS error onto the credential-issuer taxonomy. Reads
/// only the `error` code + HTTP status — never `error_description`,
/// which can echo back submitted material (AADSTS messages).
pub(crate) fn map_entra_error(status: reqwest::StatusCode, body: &str) -> CredentialError {
    let error_code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_default();
    let code = status.as_u16();
    let reason = if error_code.is_empty() {
        format!("Entra token endpoint returned HTTP {code}")
    } else {
        format!("Entra token endpoint returned HTTP {code} (error: {error_code})")
    };
    if code == 429 || error_code == "temporarily_unavailable" {
        return CredentialError::Throttled { reason };
    }
    match error_code.as_str() {
        "invalid_client" | "unauthorized_client" | "invalid_grant" | "access_denied" => {
            CredentialError::NotAuthorized { reason }
        }
        _ => match code {
            401 | 403 => CredentialError::NotAuthorized { reason },
            400 => CredentialError::Misconfigured { reason },
            500..=599 => CredentialError::Backend { reason },
            _ => CredentialError::Backend { reason },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn error_mapping_by_code() {
        assert!(matches!(
            map_entra_error(StatusCode::UNAUTHORIZED, r#"{"error":"invalid_client"}"#),
            CredentialError::NotAuthorized { .. }
        ));
        assert!(matches!(
            map_entra_error(StatusCode::TOO_MANY_REQUESTS, "{}"),
            CredentialError::Throttled { .. }
        ));
        assert!(matches!(
            map_entra_error(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#),
            CredentialError::Misconfigured { .. }
        ));
        assert!(matches!(
            map_entra_error(StatusCode::SERVICE_UNAVAILABLE, ""),
            CredentialError::Backend { .. }
        ));
        assert!(matches!(
            map_entra_error(StatusCode::OK, r#"{"error":"temporarily_unavailable"}"#),
            CredentialError::Throttled { .. }
        ));
    }

    #[test]
    fn error_mapping_never_leaks_description() {
        let err = map_entra_error(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_client","error_description":"AADSTS7000215 LEAKED_SECRET_xyz"}"#,
        );
        let CredentialError::NotAuthorized { reason } = err else {
            panic!("expected NotAuthorized");
        };
        assert!(reason.contains("invalid_client"));
        assert!(!reason.contains("LEAKED_SECRET_xyz"), "{reason}");
    }

    #[test]
    fn read_federated_token_missing_env_is_misconfigured() {
        // Path unset + env absent → Misconfigured (deterministic only if
        // the env var is unset in the test environment).
        if std::env::var("AZURE_FEDERATED_TOKEN_FILE").is_err() {
            assert!(matches!(
                read_federated_token(&None),
                Err(CredentialError::Misconfigured { .. })
            ));
        }
    }

    #[test]
    fn read_federated_token_reads_and_trims_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("mcpg-azure-fed-{}.jwt", std::process::id()));
        std::fs::write(&path, "  eyJ.fake.token  \n").unwrap();
        let tok = read_federated_token(&Some(path.to_string_lossy().into_owned())).unwrap();
        assert_eq!(tok, "eyJ.fake.token");
        let _ = std::fs::remove_file(&path);
    }
}
