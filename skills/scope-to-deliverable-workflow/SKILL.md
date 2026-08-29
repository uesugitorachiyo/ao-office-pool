---
name: scope-to-deliverable-workflow
description: Use when work is Tier 4 or explicitly requires a full, reusable, high-impact deliverable with multiple dependencies and acceptance gates.
---

# Scope to Deliverable Workflow

## Trigger

Use for Tier 4 work: a reusable or release-grade result whose failure has material operational impact, or work explicitly requiring the full workflow. Do not use for a small local edit, an exploratory note, or a one-off reversible task.

## Authority

The workflow organizes authorized work; it does not expand authority. Publishing, provider calls, authenticated access, credential use, destructive actions, installation, and scope changes require explicit task authority. A delivery gate cannot grant permission that the task did not grant.

## Inputs

- Outcome, users, target platform, and out-of-scope boundaries.
- Existing contracts, assets, dependencies, and known evidence.
- Acceptance criteria, privacy constraints, and permitted destinations.
- Reversibility, compatibility, and support expectations.

## Evidence

Prefer deterministic evidence: versioned contracts, schemas, manifests, hashes, tests, clean-environment runs, and reproducible command output. Record which evidence satisfies each gate. Separate build evidence from release authorization and do not treat documentation as execution proof.

## Procedure

1. Classify the work and state why the full workflow applies.
2. Freeze the outcome, scope, exclusions, assumptions, and authority boundary.
3. Enumerate the smallest complete deliverables and their dependencies.
4. Order vertical slices so each produces testable evidence and a reversible checkpoint.
5. Define hard gates for contract, implementation, privacy, portability, verification, packaging, and handoff.
6. Execute one slice at a time; close its gate before depending on it.
7. Reconcile payload, documentation, metadata, and tests against the same source identity.
8. Mark ready only when every acceptance criterion has direct evidence. Keep publication separate unless authorized.

## Outputs

Return the frozen scope, deliverable register, dependency order, gate matrix, verification evidence, remaining risks, and handoff package. Every deliverable must have an acceptance condition and evidence reference.

## Stop conditions

Stop at the affected gate when required assets are missing, evidence conflicts, a dependency is unqualified, privacy or portability fails, or progress needs new authority. Report the smallest bounded blocker and the next safe action; do not silently reduce acceptance criteria.

## Privacy

Keep durable artifacts free of credentials, raw private state, authenticated provider data, and private conversation content. Use relative references, sanitized evidence, and explicit exclusions. Retain only what the delivery contract requires.

## Handoff

Hand off scope and exclusions, exact source identity, deliverables, gate results, reproducible verification, known limitations, rollback or recovery guidance, and the next authorized action. Distinguish built, verified, ready, and published states.
