# AO Office Pool Design

Date: 2026-08-10
Status: approved direction, revised after V1.1 and transferred V1.2 audit

## Outcome

AO Office Pool will provide five isolated Windows execution offices over one
shared, version-pinned AO stack. A project conversation claims or resumes one
office before governed work. AO Mission records and routes the objective;
downstream components plan, authorize, execute, evaluate, and report within
their existing authority boundaries.

The public v1.2.0 release must be installable on a local Windows NTFS volume,
must preserve validated V1.1 safety behavior, and must close all nineteen known
V1.2 blockers. macOS and the external development drive remain construction and
staging surfaces.

## Source posture

V1.1 is a validated behavior and regression reference. Its archived copy is
reference-only because live ownership was removed and its capability bindings
depended on sibling local sources. The transferred V1.2 candidate is unqualified
and contains known defects, stale qualification evidence, inconsistent
authority documents, and useful modernization work.

AO Office Pool will reimplement the product in a new repository. The team may
port invariants, schemas, test scenarios, compatibility facts, and verified
component identities after review. The team must not copy predecessor code,
private state, absolute paths, user identities, contaminated skill text, or old
acceptance claims into the new authority chain.

## Product boundary

AO Office Pool owns:

- atomic allocation of offices O1 through O5;
- private receipt-bound ownership, protected inspection, and resume;
- connected-project binding and output-path enforcement;
- an independent byte-identical AO2 runtime copy for each office;
- shared immutable AO component packages and truthful capability metadata;
- clean release, recovery-required transition, emergency recovery, update, and
  rollback;
- exact-field public status and allowlisted support exports;
- Windows packaging, installation, verification, qualification, and release.

The connected project owns mission records, workgraphs, checkpoints, evidence,
and deliverables under its `.ao/` state root and normal project paths. Offices
hold only coordination, runtime, protected history, and transient work state.

## End-state layout

The public development repository contains only source and releasable material:

```text
ao-office-pool/
├── .github/
├── cmd/
├── internal/
├── schemas/
├── skills/
├── scripts/
├── tests/
├── docs/
├── manifests/
├── packaging/
└── .local/                 ignored handoffs, drafts, and mission state
```

Development checkouts never live in tracked source folders. Each AO repository
uses `.local/sources/<component-name>/`, downloads use `.local/downloads/`, and
the generated Windows tree uses `.local/staging/windows-x86_64/`. AO Mission
runs with the repository root as its working directory. Its source checkout is
not a connected-project root.

The finalized Windows installation adds generated private state:

```text
<installation-root>\
├── bin\
├── components\             shared immutable component packages
├── manifests\
├── pool.json
├── offices\
│   ├── O1\
│   │   ├── office-state.json
│   │   ├── runtime\versions\
│   │   ├── history\
│   │   └── work\
│   ├── O2\
│   ├── O3\
│   ├── O4\
│   └── O5\
├── operator-secrets\
├── updates\
└── support-bundles\
```

The installer chooses and records one fixed local NTFS root. Public source and
release metadata must not hardcode a username or developer path.

Shared component packages use `components/<component>/<version>/`. The accepted
AO2 package may be staged there, but activation copies its verified runtime
tree into each `offices/O1` through `offices/O5` runtime version directory.
AO Architecture remains a source and contract reference unless a later lock
records a separately qualified runtime asset.

[The stack layout contract](../../STACK_LAYOUT.md) defines every development,
staging, Production, and connected-project path. The machine-readable copy is
`manifests/stack-layout.json`. AO Mission must verify both before Task 1.

## AO workflow and authority

```text
conversation
  -> claim or resume office
  -> AO Mission record and route
  -> Blueprint requirements and authorization when needed
  -> Atlas decomposition for oversized, mutation-class, or long work
  -> Foundry and Forge coordination
  -> Covenant authority decision
  -> AO2 bounded execution
  -> Arena, Crucible, Sentinel, and Promoter gates when required
  -> Command and Mission readback
  -> checkpoint and retain, release, or enter recovery-required
```

AO Mission is the prompt and continuation entrypoint. It cannot execute, approve
policy, call providers, publish, deploy, access credentials, or mutate a
repository. AO2 remains the receipt-bound execution runtime. Evaluation and
readback components cannot gain execution or promotion authority through
routing.

## Office and ownership model

The product shares immutable component packages rather than copying every AO
repository into each office. Each office receives:

- a fixed office identifier and monotonic generation;
- one active owner, task, and connected-project binding;
- a private receipt stored outside public output;
- a non-secret resume pointer that cannot authorize by itself;
- an independent AO2 runtime tree whose accepted bytes match the other offices;
- protected transient execution state and history.

A sixth claimant receives a clear full-capacity result. The product does not
queue, steal, interrupt, expire, or reassign active work. Pinned work stays
occupied until an authorized transition. Ordinary bounded conversation can
complete and release without creating a file.

## V1.1 inheritance contract

V1.2 must retain these behaviors through new tests:

- atomic first-free O1–O5 claims and one clear sixth-claim failure;
- exact receipt, owner, generation, office, task, and project authorization;
- private same-task resume without receipt enumeration;
- exact-field, secret-free, nonmutating public status;
- no automatic expiry for pinned work;
- connected-project output enforcement against traversal, aliases, links,
  reparse points, 8.3 names, and delete/recreate identity changes;
- byte preservation for unknown residue and `recovery-required` before reuse;
- exact-key, office, and generation emergency release with evidence retention;
- all-free runtime activation, five independent equal runtime copies, and full
  rollback at every partial-failure point;
- an independent trust anchor that detects executable-plus-manifest
  substitution;
- truthful distinction among source-present, verified, tested, activated, and
  routed capabilities;
- no scheduler, hardware controller, automatic queue, stale auto-release,
  unsolicited network updater, or permanent background service.

V1.1's seven skills and thirteen accessory families establish required
capability coverage, not permission to import old files. V1.1 proved AO2 as an
office executable; most accessory implementations remained source-visible or
guidance-only. V1.2 must qualify each executable readiness claim from scratch.

## V1.2 blocker closure contract

Each blocker requires a failing regression, a bounded correction, a passing
regression, and a durable requirement-to-test record:

| ID | Required correction |
|---|---|
| B01 | Continuing ordinary conversation does not imply pinned mode. |
| B02 | Conversation-only completion does not require a file deliverable. |
| B03 | Local Mission and platform Goal state reconcile or stop with an exact conflict. |
| B04 | Runtime versions are safe Windows path segments with physical containment. |
| B05 | Missing or corrupt resume pointers cannot create duplicate owner claims. |
| B06 | Normal claim output never exposes the raw owner key. |
| B07 | Resume proves task, chat, project, office, generation, and receipt identity. |
| B08 | Cancel and replacement checkpoint and execute an authorized release transition. |
| B09 | Office release and receipt/pointer retirement are crash-consistent. |
| B10 | Dirty normal release rejects or enters a distinct recovery state. |
| B11 | Suite fingerprints bind every semantic evidence input consumed by tests. |
| B12 | Qualification atomically records a hash-bound promotion state. |
| B13 | The critical matrix contains the exact current assertion set. |
| B14 | Readability gates constrain instruction lines without compressing semantics. |
| B15 | Root agent instructions retain the correct authority order. |
| B16 | Specifications name real manifest-builder code and tests. |
| B17 | Acceptance rows bind to test modules that exist. |
| B18 | Architecture, finalizer, verifier, and durable lifecycle agree. |
| B19 | Every public claim requires a validated connected-project binding. |

No older P01–P75, 152/152, 171-pass, or independent score can close these rows.

## Skills and context economy

V1.1 contains 24 archived `SKILL.md` files but only seven canonical product
skills. Two canonical workflow skills exceed 200 lines, and several skill or
reference files contain unrelated project paths and dated rules. V1.2 will
redesign these workflows instead of copying them.

Skill rules:

- `SKILL.md` has a hard maximum of 200 physical lines and a target near 120;
- YAML frontmatter contains only `name` and `description`;
- trigger and non-trigger boundaries remain concise in `description`;
- detailed rubrics, examples, and modes move to one-level `references/`;
- deterministic repeated work belongs in small tested `scripts/`;
- skill folders contain no README, changelog, or install guide;
- files contain no absolute path, user identity, stale version/count, unrelated
  project rule, or copied evidence;
- the team inventories existing skills and updates one before creating another;
- validation checks line count, frontmatter, names, references, duplication,
  private paths, metadata, trigger behavior, and forward behavior.

Root `AGENTS.md` and other always-loaded instructions should stay below about
200 lines and 2,000 tokens. Handoffs preserve paths, decisions, verification,
blockers, and the exact next action. They do not paste raw files or tool output.
Ordinary work uses compact routing; reusable, ambiguous, high-risk, critical,
or explicitly requested work receives stronger gates.

## Public and private data

Git may contain source, schemas, documentation, sanitized fixtures,
public-safe test evidence, checksums, SBOMs, licenses, and release metadata.

Git and public release archives exclude:

- prompts, objectives, raw transcripts, and private model output;
- owner identifiers, receipts, recovery keys, and resume-pointer values;
- absolute developer or connected-project paths;
- live office state, locks, work, and private execution history;
- credentials, tokens, environment files, and raw support bundles.

Release construction uses an allowlist. The leak scanner rejects forbidden
paths, known local path forms, private state filenames, unsafe links, and
secret-shaped values before publication.

## Windows qualification

Windows qualification covers:

- native x86-64 executable identity and supported version commands;
- NTFS file identity, locks, ACLs, atomic replacement, and interruption;
- drive-letter, UNC, extended-path, case-folding, separator, and path-length
  behavior;
- reserved device names, trailing spaces and periods, and invalid segments;
- junction, reparse-point, hard-link, symlink, 8.3, and traversal rejection;
- PowerShell install, update, rollback, uninstall, and verification;
- Windows Defender-compatible packaging and complete process cleanup;
- five independent runtime copies with equal accepted bytes.

macOS tests may validate portable logic, manifests, schemas, and archive rules.
They cannot establish NTFS identity, locking, ACL, native executable, or
Production claims.

## Failure behavior

Security, ownership, identity, and path failures stop before mutation. Unknown
state is preserved. Runtime activation occurs only while all offices are free
and restores the prior accepted state after any partial failure. Public output
uses explicit constructors rather than recursive redaction. Logs and support
bundles record sanitized diagnostics without private values.

## Delivery phases

Months 1–6 end with a private Windows developer preview after B01–B19 closure.
Months 7–12 redesign the skills, activate the advanced AO stack, qualify Pulse,
RSI, evaluation, readback, endurance, recovery, and security behavior, and then
produce a public v1.2.0 release candidate. Publication requires exact-byte
independent reproduction and owner approval.

## Non-goals for v1.2.0

- cloud tenancy or a public network API;
- a scheduler or automatic waiting queue;
- automatic stale release, work stealing, or reprioritization;
- hardware control or resource throttling;
- unsolicited network updates or a permanent background service;
- importing predecessor identities, receipts, office state, or acceptance
  authority.
