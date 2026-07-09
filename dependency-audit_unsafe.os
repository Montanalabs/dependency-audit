#! VULNERABLE dependency-audit — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant auditDep confidence 70

let raw = fetch<web>
privileged { auditDep(raw) }  # tainted -> tool: REJECTED
