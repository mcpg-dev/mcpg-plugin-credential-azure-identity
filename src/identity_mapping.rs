//! Identity → target scope resolution for
//! `dev.mcpg.credential.azure-identity`.

use mcpg_plugin_protocol::types::PluginIdentity;

use crate::config::{IdentityMapping, TargetConfig};

#[derive(Debug)]
pub(crate) enum Resolution {
    /// Request a token for this scope. `identity_derived` is true when
    /// the scope came from caller-controlled identity (scope_template).
    Scope {
        value: String,
        identity_derived: bool,
    },
    EmptyDerived {
        reason: String,
    },
    SubstitutionFailed {
        field: String,
    },
}

/// A scope/resource is valid only if it is a syntactically well-formed
/// `https://` URL with a non-empty host and no userinfo, and contains
/// no whitespace/control chars. The value flows into the `scope` /
/// `resource` form param sent to Entra/IMDS; rejecting anything that
/// isn't a clean https URI stops a crafted claim from redirecting the
/// token request or smuggling an extra form field.
pub(crate) fn is_valid_scope(scope: &str) -> bool {
    if scope.is_empty() || scope.len() > 2048 {
        return false;
    }
    if scope.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Ok(url) = url::Url::parse(scope) else {
        return false;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    // Require a DNS-name host (not an IP literal): real Azure resource
    // scopes are always domain names, and this keeps the value from ever
    // resembling a connect target.
    matches!(url.host(), Some(url::Host::Domain(d)) if is_plausible_host(d))
}

/// A token-resource host must look like a real DNS hostname: non-empty,
/// only `[A-Za-z0-9.-]`, no leading/trailing dot, and at least one
/// alphanumeric char. `url` will happily normalise junk like
/// `https:///.default` to host `.default`; reject that shape.
fn is_plausible_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && host.bytes().any(|b| b.is_ascii_alphanumeric())
}

pub(crate) fn resolve_scope(identity: &PluginIdentity, target: &TargetConfig) -> Resolution {
    match target.identity_mapping {
        IdentityMapping::Static => Resolution::Scope {
            value: target.scope.clone(),
            identity_derived: false,
        },
        IdentityMapping::ScopeTemplate => {
            let template = target.scope_template.as_deref().unwrap_or("");
            substitute(template, identity)
        }
    }
}

fn substitute(template: &str, identity: &PluginIdentity) -> Resolution {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut placeholder = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                placeholder.push(ch);
            }
            if !closed {
                return Resolution::SubstitutionFailed {
                    field: format!("unterminated placeholder `${{{placeholder}`"),
                };
            }
            let field = placeholder
                .strip_prefix("identity.")
                .unwrap_or(placeholder.as_str());
            match resolve_field(field, identity) {
                Some(s) if !s.is_empty() => out.push_str(&s),
                _ => {
                    return Resolution::SubstitutionFailed {
                        field: field.to_owned(),
                    };
                }
            }
        } else {
            out.push(c);
        }
    }
    if out.is_empty() {
        Resolution::EmptyDerived {
            reason: "scope template substitution produced an empty scope".into(),
        }
    } else {
        Resolution::Scope {
            value: out,
            identity_derived: true,
        }
    }
}

fn resolve_field(field: &str, identity: &PluginIdentity) -> Option<String> {
    match field {
        "subject_id" => identity.subject_id.clone(),
        "kind" => Some(identity.kind.clone()),
        "trust_level" => Some(identity.trust_level.clone()),
        "auth_provider" => identity.auth_provider.clone(),
        f if f.starts_with("attributes.") => {
            let key = &f["attributes.".len()..];
            identity.attributes.get(key).cloned()
        }
        f if let Some(idx) = parse_indexed(f, "roles") => identity.roles.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "groups") => identity.groups.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "scopes") => identity.scopes.get(idx).cloned(),
        _ => None,
    }
}

fn parse_indexed(field: &str, name: &str) -> Option<usize> {
    let prefix = format!("{name}[");
    let rest = field.strip_prefix(&prefix)?;
    let inner = rest.strip_suffix(']')?;
    inner.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BaseAuth;
    use std::collections::BTreeMap;

    fn ident(subject: Option<&str>) -> PluginIdentity {
        let mut attrs = BTreeMap::new();
        attrs.insert("resource".into(), "storage.azure.com".into());
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: subject.map(str::to_owned),
            auth_provider: Some("entra".into()),
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: attrs,
        }
    }

    fn target(mapping: IdentityMapping, scope: &str, template: Option<&str>) -> TargetConfig {
        TargetConfig {
            tenant_id: "t".into(),
            client_id: "c".into(),
            scope: scope.into(),
            resource: String::new(),
            base_auth: BaseAuth::ClientSecret {
                client_secret: "s".into(),
            },
            identity_mapping: mapping,
            scope_template: template.map(str::to_owned),
            allowed_scopes: None,
            max_cache_ttl_ms: 3_600_000,
        }
    }

    #[test]
    fn scope_validation_accepts_https() {
        assert!(is_valid_scope("https://storage.azure.com/.default"));
        assert!(is_valid_scope("https://graph.microsoft.com/.default"));
        assert!(is_valid_scope("https://management.azure.com"));
    }

    #[test]
    fn scope_validation_rejects_injection() {
        assert!(!is_valid_scope(""));
        assert!(!is_valid_scope("http://storage.azure.com/.default"));
        assert!(!is_valid_scope("not-a-url"));
        assert!(!is_valid_scope("https://user:pass@evil.com/.default"));
        assert!(!is_valid_scope("https://x/.default scope=extra"));
        assert!(!is_valid_scope("https:///.default"));
        assert!(!is_valid_scope("ftp://x"));
        // IP-literal hosts are rejected (real scopes are DNS names).
        assert!(!is_valid_scope("https://127.0.0.1/.default"));
        assert!(!is_valid_scope("https://0x7f000001/.default"));
        assert!(!is_valid_scope("https://[::1]/.default"));
    }

    #[test]
    fn static_returns_configured_not_derived() {
        let r = resolve_scope(
            &ident(Some("x")),
            &target(
                IdentityMapping::Static,
                "https://storage.azure.com/.default",
                None,
            ),
        );
        match r {
            Resolution::Scope {
                value,
                identity_derived,
            } => {
                assert_eq!(value, "https://storage.azure.com/.default");
                assert!(!identity_derived);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn template_substitutes_attribute_derived() {
        let r = resolve_scope(
            &ident(Some("x")),
            &target(
                IdentityMapping::ScopeTemplate,
                "",
                Some("https://${identity.attributes.resource}/.default"),
            ),
        );
        match r {
            Resolution::Scope {
                value,
                identity_derived,
            } => {
                assert_eq!(value, "https://storage.azure.com/.default");
                assert!(identity_derived);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn template_substitution_failure_surfaces_field() {
        let r = resolve_scope(
            &ident(None),
            &target(
                IdentityMapping::ScopeTemplate,
                "",
                Some("https://${identity.subject_id}/.default"),
            ),
        );
        match r {
            Resolution::SubstitutionFailed { field } => assert_eq!(field, "subject_id"),
            other => panic!("{other:?}"),
        }
    }
}
