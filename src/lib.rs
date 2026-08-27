#![forbid(unsafe_code)]

//! The second gate: may this identity do this, here.
//!
//! ADR-0019 clause 2 orders them, and the order does not vary by transport:
//!
//! ```text
//! identity  ->  authentication  ->  authorization
//! who is claimed    is the claim true    may this true identity do this
//! ```
//!
//! **This runs before any actual work, at all three points.** Receiving,
//! processing and sending each ask a different question of the same identity —
//! whether this connection may post here, whether this Party's work may run in
//! this Process, whether Xmip may present this identity to that target — and
//! none of them is answered by the others.
//!
//! Authentication happens once, where the credential arrives. Authorization
//! happens every time something is about to be done.

use std::error::Error;
use std::fmt;
use xmip_context::{AlignmentResult, IdentityFacts, OnMisalignment};
use xmip_core::Layer;

/// Which of the three points is asking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// May this connection post a Stream into this Receive Location.
    Receive,
    /// May this Party's work run in this Xmip Process.
    Process,
    /// May Xmip present this identity to this target.
    Send,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Receive => "receive",
            Self::Process => "process",
            Self::Send => "send",
        })
    }
}

/// What is about to be done, and where.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub action: Action,
    /// The artifact — a Receive Location, an Xmip Process, a Send Location.
    pub artifact: String,
    /// The Contract, where one has been identified.
    pub contract: Option<String>,
    /// The Path, where one applies.
    pub path: Option<String>,

    /// When the work is being attempted, in unix nanoseconds.
    ///
    /// Not when the identity arrived. A Journey may have waited days for a
    /// human between the two, and the gap is the whole reason this gate runs
    /// again rather than trusting what receive concluded.
    pub at: i128,
}

impl Attempt {
    #[must_use]
    pub fn new(action: Action, artifact: impl Into<String>) -> Self {
        Self {
            action,
            artifact: artifact.into(),
            contract: None,
            path: None,
            at: 0,
        }
    }

    /// When this is being attempted. `Clock::unix_timestamp_nanos`.
    #[must_use]
    pub const fn at(mut self, unix_nanos: i128) -> Self {
        self.at = unix_nanos;
        self
    }

    #[must_use]
    pub fn on_contract(mut self, contract: impl Into<String>) -> Self {
        self.contract = Some(contract.into());
        self
    }

    #[must_use]
    pub fn on_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

/// What the gate concluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Allowed,
    /// Refused, and by whom.
    ///
    /// Both halves matter to an operator: "denied" without the rule that denied
    /// it is a message that sends someone reading policy for an afternoon.
    Denied { by: String, reason: String },
}

impl Decision {
    #[must_use]
    pub const fn allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    #[must_use]
    pub fn denied(by: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Denied {
            by: by.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => f.write_str("allowed"),
            Self::Denied { by, reason } => write!(f, "denied by {by}: {reason}"),
        }
    }
}

#[derive(Debug)]
pub struct AuthorizeError {
    pub message: String,
}

impl fmt::Display for AuthorizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for AuthorizeError {}

/// One policy, implemented by one module.
///
/// A policy may abstain. Returning `None` means "no opinion", which is not the
/// same as allowing: see [`authorize`] for what happens when nothing has one.
pub trait Authorizer: Send + Sync {
    fn name(&self) -> &str;

    /// The layer this policy judges.
    ///
    /// ADR-0019 clause 6: authorization is evaluated per layer, and neither
    /// implies the other. Transport authorization answers whether this
    /// connection may post here at all; message authorization answers whether
    /// this named Party may send this contract on this Path.
    fn layer(&self) -> Layer;

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision>;
}

/// Run the authorization gate before any work is done.
///
/// Three things happen, in this order:
///
/// 1. **Misalignment is settled first.** ADR-0019 clause 7 puts `reject` here
///    rather than at routing, because misalignment is a policy outcome and not
///    a routing fault.
/// 2. **Every policy for every applicable layer is asked.** Both must pass
///    where both apply, and a policy that abstains does not count as assent.
/// 3. **Nothing having an opinion is a denial.** An unconfigured gate is
///    closed, exactly as an unconfigured Receive Location accepts nothing.
///    A policy engine that defaults to yes is a policy engine that is not
///    consulted the day it matters.
#[must_use]
pub fn authorize(
    policies: &[&dyn Authorizer],
    identity: &IdentityFacts,
    attempt: &Attempt,
    on_misalignment: OnMisalignment,
) -> Decision {
    if identity.alignment == AlignmentResult::Misaligned
        && on_misalignment == OnMisalignment::Reject
    {
        return Decision::denied(
            "alignment",
            format!(
                "the transport identity and the message identity resolved to different Parties, \
                 and this location rejects misalignment"
            ),
        );
    }

    // Message-layer policies apply only where a message identity exists. Most
    // of the estate has none — a raw CSV carries no message identity at all.
    let applicable = |layer: Layer| match layer {
        Layer::Transport => true,
        Layer::Message => identity.message.is_some(),
    };

    let mut consulted = 0_usize;

    for policy in policies.iter().filter(|policy| applicable(policy.layer())) {
        consulted += 1;

        if let Some(Decision::Denied { by, reason }) = policy.decide(identity, attempt) {
            return Decision::Denied { by, reason };
        }
    }

    if consulted == 0 {
        return Decision::denied(
            "xmip",
            format!(
                "no policy is configured for {} on '{}'",
                attempt.action, attempt.artifact
            ),
        );
    }

    Decision::Allowed
}

/// Refuses an identity that was proven too long ago, or never said when.
///
/// The policy a waiting Journey needs. A Process that sat for three days
/// waiting for a human resumes holding a record of an authentication that
/// happened before the weekend, and whether that is still good enough is a
/// question only a rule with a clock can answer.
///
/// Transport layer, because that is where proof of the connection lives. A
/// message-layer signature does not go stale in the same way — it proves what
/// the content was when it was signed, not that anybody is still trusted.
pub struct Freshness {
    /// How old an authentication may be, in nanoseconds.
    pub within: i128,
}

impl Freshness {
    /// Whatever the deployment considers a working session.
    #[must_use]
    pub const fn within_seconds(seconds: i64) -> Self {
        Self {
            within: (seconds as i128) * 1_000_000_000,
        }
    }
}

impl Authorizer for Freshness {
    fn name(&self) -> &str {
        "freshness"
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        match identity.transport.age_at(attempt.at) {
            None => Some(Decision::denied(
                "freshness",
                "the identity does not record when it was authenticated",
            )),
            Some(age) if age > self.within => Some(Decision::denied(
                "freshness",
                format!(
                    "authenticated {} seconds ago, and this allows {}",
                    age / 1_000_000_000,
                    self.within / 1_000_000_000
                ),
            )),
            Some(_) => Some(Decision::Allowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmip_context::{Alignment, AuthenticatedIdentity, Verified};
    use xmip_core::PartyId;
    use xmip_core::{mechanism, Established};

    struct Policy {
        name: &'static str,
        layer: Layer,
        answer: Option<Decision>,
    }

    impl Authorizer for Policy {
        fn name(&self) -> &str {
            self.name
        }

        fn layer(&self) -> Layer {
            self.layer
        }

        fn decide(&self, _identity: &IdentityFacts, _attempt: &Attempt) -> Option<Decision> {
            self.answer.clone()
        }
    }

    fn allows(name: &'static str, layer: Layer) -> Policy {
        Policy { name, layer, answer: Some(Decision::Allowed) }
    }

    fn denies(name: &'static str, layer: Layer, why: &'static str) -> Policy {
        Policy { name, layer, answer: Some(Decision::denied(name, why)) }
    }

    fn abstains(name: &'static str, layer: Layer) -> Policy {
        Policy { name, layer, answer: None }
    }

    fn tls(party: Option<PartyId>) -> AuthenticatedIdentity {
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
            Established::Passed,
            Verified::Proven,
        );

        match party {
            Some(party_id) => identity.resolving_to(party_id),
            None => identity,
        }
    }

    fn isa06(party: Option<PartyId>) -> AuthenticatedIdentity {
        let identity = AuthenticatedIdentity::new(
            mechanism::edi_x12_interchange(),
            "ISA06=PARTNERX",
            Established::Detected,
            Verified::Claimed,
        );

        match party {
            Some(party_id) => identity.resolving_to(party_id),
            None => identity,
        }
    }

    fn transport_only() -> IdentityFacts {
        IdentityFacts::evaluate(Alignment::None, tls(Some(PartyId::new(1))), None)
    }

    fn receiving() -> Attempt {
        Attempt::new(Action::Receive, "partner-x")
    }

    #[test]
    fn nothing_configured_is_a_denial_rather_than_an_allowance() {
        // The same failure mode as an unconfigured Receive Location. A policy
        // engine that defaults to yes is one that is not consulted the day it
        // matters.
        let decision = authorize(&[], &transport_only(), &receiving(), OnMisalignment::Accept);

        assert!(!decision.allowed());
        assert_eq!(
            decision.to_string(),
            "denied by xmip: no policy is configured for receive on 'partner-x'"
        );
    }

    #[test]
    fn one_denial_ends_it_however_many_others_allow() {
        let yes = allows("open", Layer::Transport);
        let no = denies("rate-limit", Layer::Transport, "over quota");
        let policies: [&dyn Authorizer; 2] = [&yes, &no];

        let decision = authorize(
            &policies,
            &transport_only(),
            &receiving(),
            OnMisalignment::Accept,
        );

        assert_eq!(decision.to_string(), "denied by rate-limit: over quota");
    }

    #[test]
    fn abstaining_is_not_assent() {
        // A policy with no opinion leaves the gate exactly as it found it. If
        // it is the only one applicable, nothing has been authorised.
        let quiet = abstains("quiet", Layer::Transport);
        let policies: [&dyn Authorizer; 1] = [&quiet];

        let decision = authorize(
            &policies,
            &transport_only(),
            &receiving(),
            OnMisalignment::Accept,
        );

        assert!(decision.allowed(), "one applicable policy was consulted");
    }

    #[test]
    fn a_message_policy_is_not_consulted_when_there_is_no_message_identity() {
        // Most of the estate. A raw CSV carries no message identity, so a
        // message-layer rule has nothing to judge — and its absence must not
        // leave the gate looking unconfigured either.
        let transport = allows("connection", Layer::Transport);
        let message = denies("contract", Layer::Message, "would have denied");
        let policies: [&dyn Authorizer; 2] = [&transport, &message];

        let decision = authorize(
            &policies,
            &transport_only(),
            &receiving(),
            OnMisalignment::Accept,
        );

        assert!(decision.allowed(), "got {decision}");
    }

    #[test]
    fn both_layers_must_pass_where_both_apply() {
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            tls(Some(PartyId::new(1))),
            Some(isa06(Some(PartyId::new(2)))),
        );

        let transport = allows("connection", Layer::Transport);
        let message = denies("contract", Layer::Message, "not this contract");
        let policies: [&dyn Authorizer; 2] = [&transport, &message];

        let decision = authorize(&policies, &facts, &receiving(), OnMisalignment::Accept);

        assert_eq!(decision.to_string(), "denied by contract: not this contract");
    }

    #[test]
    fn misalignment_is_refused_here_and_not_at_routing() {
        // ADR-0019 clause 7. Misalignment is a policy outcome, not a routing
        // fault, so `reject` lands in authorization.
        let facts = IdentityFacts::evaluate(
            Alignment::Strict,
            tls(Some(PartyId::new(1))),
            Some(isa06(Some(PartyId::new(2)))),
        );
        let yes = allows("open", Layer::Transport);
        let policies: [&dyn Authorizer; 1] = [&yes];

        let rejected = authorize(&policies, &facts, &receiving(), OnMisalignment::Reject);
        let accepted = authorize(&policies, &facts, &receiving(), OnMisalignment::Accept);

        assert!(!rejected.allowed());
        assert!(accepted.allowed(), "the default records it and proceeds");
    }

    const SECOND: i128 = 1_000_000_000;

    #[test]
    fn a_journey_that_waited_too_long_is_refused_when_it_resumes() {
        // The Process waited three days for a human. The certificate that got
        // the Message in may have expired in the meantime, and the record of
        // that authentication is not a licence to act now.
        let arrived_at = 1_000 * SECOND;
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            tls(Some(PartyId::new(1))).at(arrived_at),
            None,
        );

        let fresh = Freshness::within_seconds(3600);
        let policies: [&dyn Authorizer; 1] = [&fresh];

        let straight_away = authorize(
            &policies,
            &facts,
            &Attempt::new(Action::Send, "Billing").at(arrived_at + 60 * SECOND),
            OnMisalignment::Accept,
        );
        let three_days_later = authorize(
            &policies,
            &facts,
            &Attempt::new(Action::Send, "Billing").at(arrived_at + 3 * 86_400 * SECOND),
            OnMisalignment::Accept,
        );

        assert!(straight_away.allowed());
        assert!(!three_days_later.allowed());
        assert!(
            three_days_later.to_string().contains("259200 seconds ago"),
            "got: {three_days_later}"
        );
    }

    #[test]
    fn an_identity_that_cannot_say_when_it_was_proven_is_not_fresh() {
        // Unrecorded and stale are different failures, and both are denials.
        let fresh = Freshness::within_seconds(3600);
        let policies: [&dyn Authorizer; 1] = [&fresh];

        let decision = authorize(
            &policies,
            &transport_only(),
            &Attempt::new(Action::Process, "Approval").at(9_999 * SECOND),
            OnMisalignment::Accept,
        );

        assert_eq!(
            decision.to_string(),
            "denied by freshness: the identity does not record when it was authenticated"
        );
    }

    #[test]
    fn the_three_points_ask_different_questions_of_one_identity() {
        // Authentication happened once. Authorization happens three times, and
        // allowing a Party to post here says nothing about whether its work may
        // run in a Process or whether Xmip may present an identity to a target.
        let receive_only = Policy {
            name: "inbound-only",
            layer: Layer::Transport,
            answer: None,
        };

        struct ByAction;

        impl Authorizer for ByAction {
            fn name(&self) -> &str {
                "by-action"
            }

            fn layer(&self) -> Layer {
                Layer::Transport
            }

            fn decide(&self, _identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
                match attempt.action {
                    Action::Receive => Some(Decision::Allowed),
                    Action::Process | Action::Send => {
                        Some(Decision::denied("by-action", "inbound only"))
                    }
                }
            }
        }

        let by_action = ByAction;
        let policies: [&dyn Authorizer; 2] = [&receive_only, &by_action];
        let facts = transport_only();

        for (action, artifact, expected) in [
            (Action::Receive, "partner-x", true),
            (Action::Process, "Approval", false),
            (Action::Send, "Billing", false),
        ] {
            let decision = authorize(
                &policies,
                &facts,
                &Attempt::new(action, artifact),
                OnMisalignment::Accept,
            );

            assert_eq!(decision.allowed(), expected, "{action} on {artifact}");
        }
    }
}
