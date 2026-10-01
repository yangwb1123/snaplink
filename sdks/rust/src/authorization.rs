//! Who Snaplink says the bearer is, and what that subject may do.
//!
//! This is the read side of an authorization decision: identity from
//! `/userinfo`, and the permission, role, and menu projections from the
//! `/permissions/me`, `/roles/me`, and `/menus/me` family.
//!
//! The server remains the authority for every decision. This exists so a caller
//! can render a navigation and hide a control it knows will be refused, without
//! hand-rolling an OAuth path it should not own. The permission rule that decides
//! `panel:*` versus `panel:read` lives in [`Authorization::allows`] so every
//! consumer applies the same one.

use crate::{Method, SnaplinkClient, SnaplinkError};
use serde::{Deserialize, Serialize};

/// A per-node action the subject may take.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MenuButton {
    pub code: String,
    pub name: String,
    /// The permission this button requires; empty means always shown.
    #[serde(default)]
    pub permission: String,
}

/// One node of the navigation tree the subject may see.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MenuNode {
    pub id: String,
    pub name: String,
    /// Route this node opens, relative to the application root.
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub icon: String,
    /// The permission this node requires; empty means always shown.
    #[serde(default)]
    pub permission: String,
    #[serde(default)]
    pub buttons: Vec<MenuButton>,
    #[serde(default)]
    pub children: Vec<MenuNode>,
}

impl MenuNode {
    /// Whether this node's own permission is held, ignoring children.
    pub fn is_visible(&self, permissions: &[String]) -> bool {
        self.permission.is_empty() || super::authorization::holds(permissions, &self.permission)
    }

    /// Whether this node and every button on it are permitted.
    pub fn actions(&self, permissions: &[String]) -> Vec<&MenuButton> {
        self.buttons
            .iter()
            .filter(|button| {
                button.permission.is_empty() || holds(permissions, &button.permission)
            })
            .collect()
    }
}

/// Everything Snaplink reports about the current bearer.
///
/// Assembled from four separate responses rather than decoded from one, so it is
/// [`Serialize`] but deliberately not [`Deserialize`]: there is no single wire
/// document with this shape, and claiming one would let a caller parse a
/// document the server never sent.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Authorization {
    /// The authenticated subject. This is the only identity worth trusting.
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// Roles held for the requested client.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Flat permission codes held for the requested client.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// The navigation tree the subject is authorized to see.
    #[serde(default)]
    pub menus: Vec<MenuNode>,
}

impl Authorization {
    /// Whether the subject holds a permission.
    ///
    /// Mirrors the server's `permissions.Matches` exactly, because a client
    /// rule that disagrees with the server is worse than no rule at all: it
    /// hides controls the server would grant and shows controls it would deny.
    ///
    /// - an exact code match grants;
    /// - `domain:*` is a **prefix** rule, so `panel:*` grants `panel:config:write`
    ///   and also `a:*` grants `a:b:c`;
    /// - a bare `*` grants everything, including a single-segment code;
    /// - an empty requirement is always granted, which is what an empty
    ///   permission on a menu node means.
    pub fn allows(&self, permission: &str) -> bool {
        holds(&self.permissions, permission)
    }

    /// Whether the subject holds a role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|held| held == role)
    }

    /// Find a menu node by id, at any depth.
    pub fn menu(&self, id: &str) -> Option<&MenuNode> {
        fn walk<'a>(nodes: &'a [MenuNode], id: &str) -> Option<&'a MenuNode> {
            for node in nodes {
                if node.id == id {
                    return Some(node);
                }
                if let Some(found) = walk(&node.children, id) {
                    return Some(found);
                }
            }
            None
        }
        walk(&self.menus, id)
    }

    /// The menu tree filtered to what this subject may open.
    ///
    /// This is a convenience for rendering, not a control: the server refuses
    /// whatever the client could still reach.
    pub fn visible_menus(&self) -> Vec<&MenuNode> {
        self.menus
            .iter()
            .filter(|node| node.is_visible(&self.permissions))
            .collect()
    }
}

/// Whether `permissions` holds `required`, following the server's rule.
///
/// Kept in step with `domains/permissions/matcher.go`. A `domain:*` grant is a
/// prefix comparison rather than an exact pair, and a bare `*` is global; both
/// details are easy to get subtly wrong and neither is visible until a control
/// is wrongly hidden or wrongly shown.
pub fn holds(permissions: &[String], required: &str) -> bool {
    if required.is_empty() {
        return true;
    }
    permissions.iter().any(|held| {
        held == "*" || held == required || matches_domain_wildcard(held, required)
    })
}

/// Whether a held code of the form `domain:*` covers `required`.
fn matches_domain_wildcard(held: &str, required: &str) -> bool {
    let Some(domain) = held.strip_suffix(":*") else {
        return false;
    };
    // The colon is part of the prefix, which is what stops `panel:*` from
    // reaching a hypothetical `panelx:read`.
    required.starts_with(&format!("{domain}:"))
}

#[derive(Debug, Deserialize)]
struct UserInfoBody {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PermissionsBody {
    #[serde(default)]
    permissions: Vec<CodeItem>,
}

#[derive(Debug, Deserialize)]
struct RolesBody {
    #[serde(default)]
    roles: Vec<CodeItem>,
}

#[derive(Debug, Deserialize)]
struct MenusBody {
    #[serde(default)]
    menus: Vec<MenuNode>,
}

/// One entry of a code list. The contract sends objects, but a bare string is
/// accepted so a caller that only projects codes is not forced to reshape them.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CodeItem {
    Object {
        #[serde(default)]
        code: String,
    },
    Code(String),
}

impl CodeItem {
    fn code(&self) -> Option<&str> {
        let code = match self {
            CodeItem::Object { code } => code.as_str(),
            CodeItem::Code(code) => code.as_str(),
        };
        // An entry with no readable code can grant nothing, so it is dropped
        // rather than surfaced as an empty string that might look like a match.
        (!code.is_empty()).then_some(code)
    }
}

impl SnaplinkClient {
    /// Read identity, permissions, roles, and menus for the current bearer.
    ///
    /// `client_id` selects the application the permission and menu projection is
    /// read for, which is why it is required rather than defaulted: one subject
    /// can hold different grants for different applications, and guessing would
    /// silently read the wrong set.
    ///
    /// All four are fetched together because they are always wanted together
    /// and a navigation tree that disagrees with the enforced permission set is
    /// worse than one extra round trip.
    pub async fn authorize(&self, client_id: &str) -> Result<Authorization, SnaplinkError> {
        let token = self
            .access_token()
            .ok_or_else(|| invalid("login is required"))?
            .to_owned();
        let userinfo: UserInfoBody = self
            .request_json(Method::Get, self.issuer_url("/userinfo")?, None, Some(&token))
            .await?;
        if userinfo.sub.trim().is_empty() {
            return Err(invalid("/userinfo returned no subject"));
        }
        let permissions: PermissionsBody = self
            .request_json(
                Method::Get,
                self.scoped_url("/permissions/me", client_id)?,
                None,
                Some(&token),
            )
            .await?;
        let roles: RolesBody = self
            .request_json(
                Method::Get,
                self.scoped_url("/roles/me", client_id)?,
                None,
                Some(&token),
            )
            .await?;
        let menus: MenusBody = self
            .request_json(
                Method::Get,
                self.scoped_url("/menus/me", client_id)?,
                None,
                Some(&token),
            )
            .await?;
        Ok(Authorization {
            subject: userinfo.sub,
            email: userinfo.email,
            name: userinfo.name,
            roles: roles
                .roles
                .iter()
                .filter_map(CodeItem::code)
                .map(str::to_owned)
                .collect(),
            permissions: permissions
                .permissions
                .iter()
                .filter_map(CodeItem::code)
                .map(str::to_owned)
                .collect(),
            menus: menus.menus,
        })
    }

    /// Read only the subject, for a caller that does not need the projections.
    pub async fn userinfo(&self) -> Result<Authorization, SnaplinkError> {
        let token = self
            .access_token()
            .ok_or_else(|| invalid("login is required"))?
            .to_owned();
        let body: UserInfoBody = self
            .request_json(Method::Get, self.issuer_url("/userinfo")?, None, Some(&token))
            .await?;
        if body.sub.trim().is_empty() {
            return Err(invalid("/userinfo returned no subject"));
        }
        Ok(Authorization {
            subject: body.sub,
            email: body.email,
            name: body.name,
            ..Authorization::default()
        })
    }

    fn issuer_url(&self, path: &str) -> Result<String, SnaplinkError> {
        let base = self
            .base_url
            .as_ref()
            .ok_or_else(|| invalid("login is required"))?;
        Ok(format!("{}{}", base.as_str().trim_end_matches('/'), path))
    }

    /// The `/me`-style endpoints take the client the projection is read for.
    fn scoped_url(&self, path: &str, client_id: &str) -> Result<String, SnaplinkError> {
        if client_id.trim().is_empty() {
            return Err(invalid("client_id is required"));
        }
        let base = self.issuer_url(path)?;
        Ok(format!(
            "{base}?client_id={}",
            percent_encode(client_id)
        ))
    }
}

/// Percent-encode a query parameter value.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn invalid(message: &str) -> SnaplinkError {
    SnaplinkError::InvalidRequest(message.to_owned())
}
