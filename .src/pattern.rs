//! The one pattern language the gate's technologies name artifacts in.
//!
//! An access list and a role both say which artifacts they cover as a name
//! with `*` in it, and each carried its own copy of the matcher until
//! 2026-09-22. Neither may depend on the other, so it lives up here
//! (ADR-0044), and a pattern means the same under either.

/// Whether a name matches a pattern, where `*` stands for any run of
/// characters and everything else stands for itself, case included.
#[must_use]
pub fn matches(pattern: &str, name: &str) -> bool {
    let mut pieces = pattern.split('*');
    let Some(head) = pieces.next() else {
        return name.is_empty();
    };
    let Some(mut rest) = name.strip_prefix(head) else {
        return false;
    };
    let mut pieces = pieces.peekable();

    while let Some(piece) = pieces.next() {
        let last = pieces.peek().is_none();
        if last {
            return rest.ends_with(piece);
        }
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }

    rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_star_stands_for_any_run_and_the_rest_for_itself() {
        assert!(matches("Billing*", "Billing"));
        assert!(matches("partner-*", "partner-x"));
        assert!(!matches("partner-*", "Partner-x"));
        assert!(matches("*", ""));
        assert!(matches("a*b*c", "axxbyyc"));
        assert!(!matches("a*b*c", "axxbyy"));
        assert!(!matches("Billing", "Billing2"));
        assert!(matches("*.xml", "orders.xml"));
    }
}
