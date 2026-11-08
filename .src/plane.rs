//! Who may ask a plane what: the one admission every plane Xmip serves to
//! its own parts asks after its handshake and before it reads a request —
//! the Storage wire between a node and a Storage node, a node's operate
//! listener, an Event cluster's serving end.
//!
//! **Decided from what the connection proved, never from what it asks.** A
//! caller's standing is what its handshake proved — a node's certificate,
//! a person's certificate and the role the node grants it, the account the
//! operating system names on a local endpoint — ranked least first; the
//! plane's rules say, for each action and operation, the least standing
//! that may ask it. A caller nothing proved asks nothing, and an operation
//! no rule names is refused: a plane is closed, not open, where its rules
//! say nothing.
//!
//! **A standing is granted by name, caller by caller** ([`granted`]): a
//! plane whose configuration lists who holds which standing grants each
//! proven caller the standing its own name is listed with, and nothing to a
//! caller no entry names. Proving a connection grants no standing.

/// One rule of a plane: the least standing that may ask `operation` for
/// `action`. `*` as the operation is every operation of that action no
/// other rule names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule {
    /// What the operation does: `read`, `write`, `act`.
    pub action: &'static str,
    /// The operation, as the plane names it on its wire, or `*`.
    pub operation: &'static str,
    /// The least standing that may ask it, in the plane's own ranking.
    pub least: u8,
}

impl Rule {
    /// `least` may ask `operation` for `action`.
    #[must_use]
    pub const fn new(action: &'static str, operation: &'static str, least: u8) -> Self {
        Self {
            action,
            operation,
            least,
        }
    }
}

/// Whether `who` — what the connection proved, `None` where it proved
/// nothing — of `standing` may ask `operation` for `action`, by `rules`:
/// the rule naming the operation, else the action's `*` rule.
///
/// # Errors
///
/// The refusal, opening REFUSED: nothing proved who asks, no rule admits
/// the operation, or the caller's standing is below the rule's.
pub fn admit(
    who: Option<&str>,
    standing: u8,
    (action, operation): (&str, &str),
    rules: &[Rule],
) -> Result<(), String> {
    let Some(who) = who else {
        return Err(format!(
            "REFUSED. Nothing proved who asks to {action} {operation}; a plane takes a call \
             from the identity its connection proved, never from what the caller says"
        ));
    };
    let rule = rules
        .iter()
        .find(|rule| rule.action == action && rule.operation == operation)
        .or_else(|| {
            rules
                .iter()
                .find(|rule| rule.action == action && rule.operation == "*")
        })
        .ok_or_else(|| format!("REFUSED. {operation} is no {action} this plane takes"))?;
    if standing >= rule.least {
        Ok(())
    } else {
        Err(format!(
            "REFUSED. {who} may not {action} {operation}: its standing is below what it asks"
        ))
    }
}

/// The standing a plane grants one proven caller: of `grants` — each a
/// name its configuration lists and the standing listed with it — the
/// least standing among the entries `names` says name this caller; `None`,
/// no standing at all, where none does. The least, so an entry granting
/// less is never outweighed by another naming the same caller otherwise.
pub fn granted<'a>(
    grants: impl IntoIterator<Item = (&'a str, u8)>,
    names: impl Fn(&str) -> bool,
) -> Option<u8> {
    grants
        .into_iter()
        .filter(|(name, _)| names(name))
        .map(|(_, standing)| standing)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_standing_is_the_callers_own_entrys_and_a_caller_no_entry_names_has_none() {
        let grants = [("CN=alice", 1), ("CN=bob", 2), ("alice.example", 0)];
        let named = |who: &'static [&'static str]| move |name: &str| who.contains(&name);
        assert_eq!(granted(grants, named(&["CN=bob"])), Some(2));
        assert_eq!(granted(grants, named(&["CN=alice"])), Some(1));
        assert_eq!(
            granted(grants, named(&["CN=alice", "alice.example"])),
            Some(0),
            "the least of the entries naming it"
        );
        assert_eq!(granted(grants, named(&["CN=mallory"])), None);
        assert_eq!(granted([], named(&["CN=alice"])), None, "closed by default");
    }

    const RULES: &[Rule] = &[
        Rule::new("read", "*", 0),
        Rule::new("read", "read_secret", 1),
        Rule::new("write", "*", 1),
    ];

    #[test]
    fn a_plane_admits_by_the_named_rule_else_the_actions_and_nothing_else() {
        assert!(admit(Some("CN=n"), 0, ("read", "read_message"), RULES).is_ok());
        let secret = admit(Some("CN=p"), 0, ("read", "read_secret"), RULES).unwrap_err();
        assert!(
            secret.starts_with("REFUSED. CN=p may not read read_secret"),
            "{secret}"
        );
        assert!(admit(Some("CN=n"), 1, ("read", "read_secret"), RULES).is_ok());
        assert!(admit(Some("CN=n"), 0, ("write", "write_secret"), RULES).is_err());
        let unknown = admit(Some("CN=n"), 9, ("act", "anything"), RULES).unwrap_err();
        assert!(unknown.contains("is no act this plane takes"), "{unknown}");
        let nobody = admit(None, 9, ("read", "read_message"), RULES).unwrap_err();
        assert!(
            nobody.starts_with("REFUSED. Nothing proved who asks"),
            "{nobody}"
        );
    }
}
