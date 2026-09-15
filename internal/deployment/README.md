# internal/deployment — DELIBERATELY EMPTY

This package contains no code and must never contain any.

**Why it exists as an empty directory:** the product never writes to a customer system. Not a
certificate, not a listener configuration, not a file. `product_specification.md` §5: *"Every write the
product performs is to its own database."*

Certificate *deployment* is the single failure mode that can end the company — a botched deploy taking
down a customer's production endpoint — and it is why an unknown vendor can be allowed to run this
binary inside a network at all.

**Architectural principle P1 (read-only architecture).**

Adding code here requires a new entry in `decision_register.md`. See
`project_1/project_1_full_development_plan.md` §3 and §4.
