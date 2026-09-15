# internal/renewal — DELIBERATELY EMPTY

This package contains no code and must never contain any.

**Why it exists as an empty directory:** `decision_register.md` C2 resolved a contradiction in which
the same document both required certificate renewal in the MVP and forbade any write path before ten
customers. The resolution was to remove the capability from the plan entirely — not to defer it.

The directory exists so that the boundary is a visible, reviewable fact in the repository rather than
a sentence in a document. If someone proposes renewal, the conversation starts here.

**Architectural principle P1 (read-only architecture) and P2 (no production write access).**

Adding code here requires a new entry in `decision_register.md` citing commercial evidence that
explicitly reopens D2. Convenience is not evidence.

See `project_1/project_1_full_development_plan.md` §3 (P1, P2) and §4.
