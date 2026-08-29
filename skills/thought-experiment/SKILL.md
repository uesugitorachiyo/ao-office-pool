---
name: thought-experiment
description: Use when material hidden-failure risk or uncertainty about repeated use could change a Windows office-pool decision.
---

# Thought Experiment

## Trigger

Use only when a consequential decision depends on behavior not established by existing deterministic checks, especially repetition, concurrency, interruption, recovery, or state-transition uncertainty. Do not use for ordinary brainstorming or when direct evidence already settles the question.

## Authority

This skill grants no authority to publish, contact providers, install software, access credentials, retain raw private state, or widen scope. Use only actions already authorized by the task. An experiment may recommend a decision; it cannot authorize that decision.

## Inputs

- The decision that uncertainty could change.
- Known invariants and accepted evidence.
- Relevant operating constraints and failure boundaries.
- The smallest representative workload.

## Evidence

Inspect deterministic local evidence first: contracts, manifests, tests, state transitions, and reproducible command output. Separate observed facts from assumptions. Never replace an available check with model judgment.

## Procedure

1. State the uncertain decision and the evidence gap.
2. Define a small set of distinct scenarios, including nominal, repeated, concurrent, interrupted, and boundary behavior when relevant.
3. For each scenario, name the invariant at risk and the observable result that would support or threaten it.
4. Run only safe, local, reversible checks within existing authority.
5. Compare observations with the invariant; do not infer success from absence of an error message.
6. State how the result changes, preserves, or blocks the decision.

## Outputs

Return a compact record containing scenarios, invariant threats, observations, unresolved uncertainty, and decision impact. Include reproducible relative commands or file references when available.

## Stop conditions

Stop and report a bounded blocker when the next useful check needs new authority, provider access, credentials, destructive action, unavailable assets, or a material scope expansion. Stop when additional scenarios cannot change the decision.

## Privacy

Keep evidence local and minimal. Do not persist raw operator state, credentials, provider responses, or private conversation data. Redact sensitive values and use public-relative references in durable artifacts.

## Handoff

Hand off the decision, tested scenarios, invariant results, remaining uncertainty, exact next safe check, and any authority still required. Never label an unobserved scenario as passed.
