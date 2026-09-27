//! Who a policy's rule is about: the one subject every authorize technology
//! names, matched one way and said one way.
//!
//! Three of the five facts the record keeps on an identity (ADR-0019 clause
//! 6) name a subject: anyone the gates authenticated, the Party the identity
//! resolved to, and the value the gate recorded, under one mechanism or any.
//! A technology that grants by more — `role` by a claim or an organizational
//! unit — extends this with its own, and matches the rest here.

use context::AuthenticatedIdentity;
use std::fmt;
use xcore::PartyId;

/// Whom a rule is for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Subject {
    /// Every identity the gates authenticated, anonymous included, resolved
    /// to a Party or not.
    Anyone,
    /// Whatever identity resolved to this Party. A Party is a shortcut to an
    /// identity, not a permission (ADR-0019 clause 4), so a partner reaching
    /// Xmip through two endpoints with two certificates is named once.
    Party(PartyId),
    /// The identity whose recorded value is exactly this — `CN=partner-x.example`,
    /// `ISA06=PARTNERX` — under this mechanism, by the name the catalog
    /// declares, or under any.
    Identity {
        mechanism: Option<String>,
        value: String,
    },
}

impl Subject {
    /// A recorded value under any mechanism.
    #[must_use]
    pub fn identity(value: impl Into<String>) -> Self {
        Self::Identity {
            mechanism: None,
            value: value.into(),
        }
    }

    /// A recorded value under one mechanism.
    #[must_use]
    pub fn identity_by(mechanism: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Identity {
            mechanism: Some(mechanism.into()),
            value: value.into(),
        }
    }

    /// Whether this identity is the subject.
    #[must_use]
    pub fn matches(&self, identity: &AuthenticatedIdentity) -> bool {
        match self {
            Self::Anyone => true,
            Self::Party(party) => identity.party_id == Some(*party),
            Self::Identity { mechanism, value } => {
                mechanism
                    .as_ref()
                    .is_none_or(|name| name == identity.mechanism.name())
                    && *value == identity.value
            }
        }
    }
}

/// How a denial names the subject: `anyone`, `Party <id>`, a value quoted as
/// it was recorded, and the mechanism before it where the rule names one.
impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anyone => f.write_str("anyone"),
            Self::Party(party) => write!(f, "Party {party}"),
            Self::Identity {
                mechanism: Some(mechanism),
                value,
            } => write!(f, "{mechanism}='{value}'"),
            Self::Identity {
                mechanism: None,
                value,
            } => write!(f, "'{value}'"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Verified;
    use xcore::{Established, mechanism};

    fn certificate() -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
            Established::Passed,
            Verified::Proven,
        )
        .resolving_to(PartyId::new(1))
    }

    #[test]
    fn a_subject_matches_by_party_by_value_under_a_mechanism_or_any_and_anyone() {
        let held = certificate();
        assert!(Subject::Anyone.matches(&held));
        assert!(Subject::Party(PartyId::new(1)).matches(&held));
        assert!(!Subject::Party(PartyId::new(2)).matches(&held));
        assert!(Subject::identity("CN=partner-x.example").matches(&held));
        assert!(Subject::identity_by("mutual-tls", "CN=partner-x.example").matches(&held));
        assert!(!Subject::identity_by("certificate", "CN=partner-x.example").matches(&held));
    }

    #[test]
    fn a_subject_is_said_one_way() {
        assert_eq!(Subject::Anyone.to_string(), "anyone");
        assert_eq!(
            Subject::Party(PartyId::new(7)).to_string(),
            format!("Party {}", PartyId::new(7))
        );
        assert_eq!(
            Subject::identity("ISA06=PARTNERX").to_string(),
            "'ISA06=PARTNERX'"
        );
        assert_eq!(
            Subject::identity_by("mutual-tls", "CN=x").to_string(),
            "mutual-tls='CN=x'"
        );
    }
}
