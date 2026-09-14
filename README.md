# xmip-core-authorize

The last gate: may this true identity do this, here. It runs before any
actual work at all three points — whether this connection may post here,
whether this Party's work may run in this Xmip Process, whether Xmip may
present this identity to that target — and answers with a `Decision`.

Authorization does not verify a credential; it is handed an authenticated
identity and decides. It is not a role model: a Party is recognized, a role is
granted (ADR-0009).

ADR-0019 orders the gates and ADR-0050 makes each technology under this
repository one mechanism at this gate; `architecture.toml` names them.
