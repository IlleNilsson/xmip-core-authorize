# xmip-core-authorize

The last gate: may this true identity do this, here. It runs before any
actual work at all three points — whether this connection may post here,
whether this Party's work may run in this Work Process, whether Xmip may
present this identity to that target — and answers with a `Decision`.

Authorization does not verify a credential; it is handed an authenticated
identity and decides. It is not a role model: a Party is recognized, a role is
granted (ADR-0009).

ADR-0019 orders the gates and ADR-0050 makes each technology under this
repository one mechanism at this gate; `architecture.toml` names them.

## One subject, one evidence walk

`authorize::subject::Subject` is whom a rule is about in every technology —
anyone, a Party, or a recorded value under one mechanism or any — matched
one way and said one way in a denial: `anyone`, `Party <id>`, `'<value>'`,
`<mechanism>='<value>'`. `acl`, `artifact` and `contract` name it as it is;
`role` extends it with a claim and an organizational unit (`Assignee`). A
policy that reads evidence reads it through `context`'s
`IdentityFacts::held` and `AuthenticatedIdentity::evidence_values`: one
entry per value, never split, so `rbac` and `role` read a list of roles or
groups as several entries of one name. `claim` judges the message identity
only, as its layer says (ADR-0050 section 5); the transport-layer policies
that read evidence read both layers.
