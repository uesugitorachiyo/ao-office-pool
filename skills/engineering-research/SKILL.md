---
name: engineering-research
description: Use when an engineering decision requires evidence synthesis, provenance checks, version assessment, or resolution of conflicting technical claims.
---

# Engineering Research

## Trigger

Use when an engineering decision cannot be justified from a single established fact. Choose Mode A for supplied or repository-local evidence. Choose Mode B only when the task requests external research or local evidence has a decision-relevant gap that authoritative external material can resolve.

## Authority

Research does not authorize provider calls, authenticated access, credential use, publishing, installation, purchases, or scope expansion. Mode B permits public read-only retrieval only when requested or necessary. Any authenticated or state-changing access needs separate task authority.

## Inputs

- The decision and the claims that must be established.
- Supplied files, manifests, binaries, tests, and reports.
- Required platform, version, provenance, and security constraints.
- Acceptable source classes and freshness needs.

## Evidence

In Mode A, begin with supplied and repository-local primary evidence. In Mode B, prefer vendor documentation, signed release artifacts, official repositories, standards, and original research. Treat community material as a lead, not proof. Record source identity, relevant date, supported claim, conflict, and uncertainty. Verify binary identity directly when hashes or signatures are available.

## Procedure

1. State the decision and convert it into independently checkable claims.
2. Select Mode A or Mode B and explain why it is permitted.
3. Inspect deterministic local evidence before interpreting it.
4. Gather the minimum authoritative evidence needed for each unresolved claim.
5. Separate direct observations, source statements, and inference.
6. Reconcile conflicts by provenance, specificity, date, and directness; do not average incompatible claims.
7. Assign each claim a supported, unsupported, or conflicting result and state its decision relevance.

## Outputs

Return the selected mode, source register, claim-to-evidence mapping, uncertainty, conflicts, and decision relevance. Include public links or portable relative references, concise paraphrases, and reproducible identity checks.

## Stop conditions

Stop with a bounded evidence gap when the next source needs credentials, provider access, payment, installation, private data, or authority not already granted. Stop when more sources cannot materially change the decision.

## Privacy

Do not copy raw private state, credentials, authenticated responses, or unrelated source content into the report. Retain only minimal claim-supporting evidence and redact sensitive values. Do not create durable private logs unless separately authorized.

## Handoff

Hand off the decision question, selected mode, sources used, supported and unresolved claims, conflicts, confidence limits, and exact next evidence needed. Never convert “not disproved” into “verified stable.”
