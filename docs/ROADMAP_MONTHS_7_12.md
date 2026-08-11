# AO Office Pool Roadmap: Months 7–12

Months 7–12 start only after the private Windows developer preview passes its
Month 6 gate. The phase ends with a public v1.2.0 release if every release gate
passes.

## Month 7: Lean skill package and context economy

Redesign the seven canonical product skills around current AO authority
boundaries. Preserve useful V1.1 behavior, remove project contamination, and
add deterministic skill validation. Inventory first and update an existing
skill before creating another.

Deliverables:

- seven portable product skills with only `name` and `description` in YAML
  frontmatter;
- hard maximum of 200 physical lines per `SKILL.md`, with a target near 120;
- one-level `references/` for detailed rubrics, examples, and mode-specific
  guidance;
- tested `scripts/` only for deterministic repeated operations;
- trigger-positive, trigger-negative, overlap, and forward-behavior tests;
- root agent instructions under about 200 lines and 2,000 tokens.

Exit gate:

- no skill contains absolute paths, user identity, stale version counts,
  unrelated projects, copied evidence, or duplicate instructions;
- ordinary tasks stay compact while reusable, ambiguous, high-risk, critical,
  or explicit work receives proportional gates;
- descriptions route correctly under a measured discovery-token budget;
- missing or unreadable references fail validation;
- skill mirrors, if the chosen clients require them, match byte-for-byte.

## Month 8: Complete AO component activation

Promote advanced AO components from recorded source or asset states to verified
Windows executable, accepted, activated, and routed states. Pin each transition
to exact source, asset, patch, license, digest, and native smoke evidence.

Deliverables:

- activated contracts for Mission, Blueprint, Atlas, Foundry, Forge, Covenant,
  Command, Arena, Crucible, Sentinel, Promoter, and the Control Plane where each
  component has a real executable role;
- explicit guidance-only state for architecture or source-only packages;
- compatibility adapters that do not widen authority;
- capability readback that reports the exact readiness level per component.

Exit gate:

- every routed executable runs a repeatable native Windows identity test;
- source presence cannot satisfy executable readiness;
- unavailable toolchains produce honest blocked status without installation;
- component failure cannot bypass Covenant or AO2 boundaries;
- shared packages remain immutable and office runtimes remain independent.

## Month 9: Pulse, RSI, evaluation, and readback boundaries

Integrate Pulse and RSI operator workflows with evidence-bound Arena, Crucible,
Sentinel, Promoter, Command, and Mission readback. Keep observation, evaluation,
promotion recommendation, policy, and execution as separate authorities.

Deliverables:

- bounded Pulse lifecycle and resume evidence;
- RSI claim-to-evidence map with explicit hold and rollback conditions;
- benchmark, hardening, regression, and promotion records bound to exact input
  and output digests;
- read-only public Command surface and protected receipt-bound diagnostics;
- provider-free deterministic fixtures for every authority transition.

Exit gate:

- no evaluator can execute, approve policy, publish, or mutate accepted state;
- Promoter cannot promote without required Sentinel and Covenant evidence;
- stale or mismatched evidence becomes an exact blocker;
- public readback uses an exact allowlist and remains nonmutating;
- Pulse and RSI retries preserve history without duplicate side effects.

## Month 10: Windows endurance, recovery, and security

Run long-duration concurrency, power-loss, process-kill, update, rollback,
reparse-point, antivirus, and storage-pressure tests on supported Windows hosts.
Complete the release threat model and security policy before public review.

Deliverables:

- 72-hour five-office mixed-workload endurance run;
- crash matrix for claim, checkpoint, release, recovery, stage, activate, and
  rollback transitions;
- ACL, handle identity, junction, hard-link, symlink, 8.3, UNC, extended-path,
  and delete/recreate adversarial suite;
- security policy, threat model, support-bundle review, and dependency/SBOM
  audit;
- recovery drills from every durable state.

Exit gate:

- no duplicate ownership, cross-project access, secret disclosure, or accepted
  state corruption occurs under fault injection;
- unknown residue remains byte-preserved and blocks reuse;
- all interrupted transitions converge to an accepted prior state or explicit
  recovery-required state;
- security review has no unresolved release blocker;
- the owner approves the public security-reporting route.

## Month 11: Release candidate and independent qualification

Freeze the release-candidate inputs and run qualification on clean Windows
hosts operated by someone other than the primary implementer. Permit only
versioned corrections followed by a complete rerun.

Deliverables:

- deterministic v1.2.0 release-candidate archive;
- final component lock, checksums, SBOM, provenance, licenses, and notices;
- clean-room install, update, rollback, recovery, support, and uninstall report;
- independent V1.1-inheritance, B01–B19, P01–P76, and advanced-stack results;
- public documentation and migration guide.

Exit gate:

- two complete runs against identical bytes produce identical accepted results;
- the evaluator reproduces every critical claim without private test data;
- the release archive contains only allowlisted files and passes leak scanning;
- O1–O5 finish free, clean, independent, and byte-equal where required;
- any correction invalidates prior qualification and starts a full rerun.

## Month 12: Public v1.2.0 release and stabilization

Publish only the exact independently qualified bytes after owner approval. Tag
the source, publish checksums and provenance, then hold a bounded stabilization
window without adding new architecture.

Deliverables:

- public `v1.2.0` source tag and Windows x86-64 release archive;
- signed or otherwise authenticated checksum set, SBOM, provenance, and notices;
- operator, security, recovery, update, and migration documentation;
- public issue and private vulnerability-reporting routes;
- post-release verification and rollback decision record.

Exit gate:

- published bytes match the qualified archive exactly;
- installation verification rejects any digest or manifest mismatch;
- public files contain no prompts, receipts, identities, recovery material,
  local paths, private history, or raw support data;
- the owner records release approval and the independent qualification digest;
- stabilization finds no issue requiring withdrawal or rollback.

## Deferred beyond v1.2.0

The release does not add a scheduler, automatic queue, automatic stale release,
hardware controller, unsolicited network updater, permanent background service,
cloud tenancy, or public network API. A later requirement and threat model must
justify any of those surfaces.
