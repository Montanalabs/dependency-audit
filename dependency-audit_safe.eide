#! Dependency-audit gate — untrusted a dependency can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires auditDep — the dependency-audit gate sink
#! @effect io
#! @confidence 70
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant auditDep confidence 70

type Dep = Pinned | Ranged | Latest
type Decision = AllowDep(Dep) | BlockDep

let raw = fetch<web>  # UNTRUSTED a dependency — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
privileged { auditDep(d) }  # act on the trusted decision only
