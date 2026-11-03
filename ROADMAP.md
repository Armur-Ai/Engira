# Engira — Roadmap

> Planning document. Each phase ships a usable standalone increment. Status: ☐
> planned · ◐ in progress · ☑ done. All ☐ today (fresh scaffold).

## Phase 0 — Foundations
- ☐ Go module `github.com/Armur-Ai/Engira`; `pkg/` engine + `cmd/engira` CLI (CLI consumes `pkg/`/API only).
- ☐ Core types: **AssessmentSnapshot** (immutable, imported), **Advisory**, **Score**, **Mapping**, **Case**, **RemediationRequest**.
- ☐ Import adapter: versioned request + supported SARIF subset, with source attribution + migration provenance (old-name → role).
- ☐ LICENSE, CI (build + `go test ./...`), versioned output schemas.

## Phase 1 — Intelligence & scoring
- ☑ Advisory ListMatcher + applicability (semver) over a pinned set; versioned store pending.
- ☐ Scoring service (CVSS vector→score) + CWE/OWASP/ATT&CK mapping, each versioned and reproducible.
- ☐ Dependency-interpretation endpoint (so Trishul can request advisory applicability through the same implementation).

## Phase 2 — Reporting
- ◐ Markdown report renderer shipped (pkg/intel RenderMarkdown); exec/SARIF renderers pending.
- ☐ Provenance + "chain and its limits" framing (no overclaiming repair/exploit).
- ☐ Deterministic rendering with golden-file tests.

## Phase 3 — Review, cases & approvals
- ☐ Assessment review/triage UI/API; case lifecycle (open → review → decided).
- ☐ Approval workflow; author attribution & immutable historical producer IDs preserved across branding.
- ☐ RemediationRequest creation for Dhantra (explicit scope, policy, constraints, approved change classes).

## Phase 4 — Retest & lifecycle
- ☐ Authorized scoped dynamic-retest requests routed to Swarm.
- ☐ Finding lifecycle tracking (open → verified-closed) with before/after evidence.
- ☐ Trend/MTTR views over time.

## Phase 5 — Disclosure & hardening
- ☐ Advisory drafting + CVE-request assistance (assistive, human-approved).
- ☐ Public/private destination binding + data-classification guardrails (public destinations never receive private assessment content by default).
- ☐ Architecture doc + suite topology (Mermaid); credentials kept server-side.

## Non-goals
- No discovery (Hayagriva), no exploitation (Swarm), no code analysis (Trishul), no applying fixes (Dhantra). Engira enriches, reports, and manages the review/case/retest lifecycle.
