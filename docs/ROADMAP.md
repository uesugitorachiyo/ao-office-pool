# AO Office Pool Roadmap: Months 1–6

Months 1–6 produce a private Windows developer preview. They do not produce a
public v1.2.0 release. Each month ends with a usable checkpoint and a blocking
exit gate.

## Program rules

- Build in the public repository on macOS; qualify Windows behavior on NTFS.
- Reimplement V1.1 invariants through contracts and tests. Do not copy its
  implementation, private state, absolute paths, or contaminated skill text.
- Treat all nineteen transferred V1.2 blockers as open until a failing test,
  correction, passing test, and durable traceability record prove closure.
- Keep capability states distinct: source-present, asset-verified, patched,
  executable-tested, accepted, activated, and routed.
- Keep AO Mission at the prompt, record, and route boundary. AO Mission does not
  execute, approve policy, call providers, publish, or mutate repositories.

## Month 1: Public foundation and inheritance baseline

Create the source lock format, public-tree leak scanner, portable manifest,
Windows path corpus, minimal agent instructions, and a machine-readable
V1.1/V1.2 requirement map. Record the seven canonical V1.1 product skills and
thirteen accessory families without importing their archived copies.

Deliverables:

- deterministic component and license lock;
- tracked-file and release-tree leak scanner;
- Windows lexical path validator plus a Windows-only physical-identity adapter
  contract;
- requirement rows for every validated V1.1 invariant and B01–B19;
- CI on macOS and Windows with no Production claims.

Exit gate:

- tracked files contain no secrets, private state, or developer-local paths;
- every component record has an exact source and digest;
- every inherited invariant and blocker maps to a named future test;
- Windows path fixtures reject reserved names, traversal, ambiguous roots, and
  unsupported segments;
- no live code or state is copied from either predecessor.

## Month 2: Five-office ownership and recovery core

Implement O1–O5 initialization, atomic first-free claim, receipt-only normal
claiming, exact resume, connected-project binding, clean release,
release-to-recovery, emergency release, public status, and protected status.
Close B04–B10 and B19 at the state-machine boundary.

Deliverables:

- one pool lock and monotonic office generations;
- private receipt and non-secret resume-pointer storage;
- atomic owner reconciliation when a pointer is absent or corrupt;
- crash-consistent office, receipt, and pointer retirement;
- explicit `free`, `occupied`, and `recovery-required` states;
- exact-field public status with no mutation side effects.

Exit gate:

- six concurrent claimants produce five unique winners and one full result;
- wrong owner, receipt, generation, office, or project fails closed;
- missing pointers cannot create duplicate same-owner claims;
- normal release refuses residue or enters a distinct recovery transition;
- emergency release preserves bytes and requires exact recovery authority;
- public inspection cannot enumerate receipts or refresh ownership.

## Month 3: AO Mission intake and durable project context

Connect office ownership to AO Mission. Store mission, checkpoint, workgraph,
and evidence references under the connected project's `.ao/` root. Correct the
conversation lifecycle instead of preserving the transferred pinned-mode
policy. Close B01–B03, B05, B07, and B08.

Deliverables:

- digest-bound mission intake and same-task continuation;
- bounded conversation completion independent of file creation;
- pinning only for an active Pursue Goal or explicit long-running task;
- exact task, chat, project, office, generation, and receipt proof for resume;
- executable cancel and replacement transitions;
- compact handoffs containing decisions, paths, verification, blockers, and
  next action rather than raw files or tool logs.

Exit gate:

- ordinary bounded conversation can claim, complete, and release cleanly;
- a continuing long task resumes the exact office without a duplicate claim;
- cancellation checkpoints durable state before exact release;
- local mission state cannot contradict platform Goal readback silently;
- another project, owner, task, or generation cannot resume protected state;
- AO Mission cannot widen its own authority.

## Month 4: Planning and governed AO2 execution

Integrate the minimum build path through Blueprint, Atlas, Foundry, Forge,
Covenant, and AO2. Use shared immutable component packages and one independent,
byte-identical AO2 runtime copy per office. Keep optional evaluation components
out of the execution path until their contracts are needed.

Deliverables:

- fixed routing rules for bounded, underspecified, oversized, mutation-class,
  and long-running work;
- Blueprint authorization and Atlas workgraph validation;
- Covenant-bound side-effect declaration and digest checks;
- argument-array AO2 launch with timeout and bounded diagnostics;
- connected-project output enforcement using Windows file identity.

Exit gate:

- blocked or unauthorized nodes cannot execute;
- source-visible components are never described as executable;
- execution rejects the pool, another project, aliases, links, 8.3 paths,
  traversal, and delete/recreate identity changes;
- five offices cannot cross-read, execute, inspect, or release;
- no AO repository is copied into an office.

## Month 5: Runtime lifecycle and evidence integrity

Implement verified runtime staging, all-free activation, rollback, support
exports, and qualification-state records. Reconcile B11–B18 across tests,
specifications, authority ordering, readability, fingerprints, and durable
promotion state.

Deliverables:

- independent pool trust anchor and exact runtime package manifest;
- transactional O1–O5 activation with interruption injection;
- semantic-input fingerprint for every consumed qualification artifact;
- real test-module mapping and exact critical assertion set;
- explicit `candidate`, `pilot-qualified`, and `release-qualified` records;
- allowlisted support bundle and public readback builders.

Exit gate:

- activation refuses any occupied office;
- failure after any office restores all prior accepted bytes and state;
- executable-plus-manifest substitution fails against the independent anchor;
- qualification cannot pass without an atomic hash-bound state transition;
- docs, tests, and finalization lifecycle agree;
- generated public and support outputs pass the leak scanner.

## Month 6: Private Windows developer preview

Freeze pilot inputs, run the complete V1.1 inheritance matrix and corrected
V1.2 blocker matrix on clean Windows hosts, rehearse install and recovery, and
issue a private developer-preview archive. This checkpoint is not public GA.

Deliverables:

- Windows x86-64 preview archive, checksums, SBOM, and provenance;
- PowerShell install, verify, update, rollback, and uninstall commands;
- exact B01–B19 closure ledger;
- complete P01–P76-equivalent pilot matrix tied to real tests;
- private operator guide and known-limitations report.

Exit gate:

- all nineteen blockers have red, correction, green, and traceability evidence;
- clean-room NTFS install and five-office smoke tests pass twice;
- all offices finish free with zero task-output residue;
- update interruption and emergency recovery preserve accepted bytes;
- an independent reviewer reproduces the pilot result;
- artifacts are labeled `developer-preview`, never Production or public v1.2.0.

Months 7–12 complete the skill redesign, advanced component activation,
endurance testing, independent release qualification, and public v1.2.0. See
[ROADMAP_MONTHS_7_12.md](ROADMAP_MONTHS_7_12.md).
