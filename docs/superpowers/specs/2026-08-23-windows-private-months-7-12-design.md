# Windows-Private Months 7–12 Design

## Purpose

AO Office Pool will advance from the qualified Windows developer preview to a
private stable release. The program supports Windows x86-64 only. It does not
add macOS or Linux support, public distribution, broad AO Stack research, or a
complex CI/CD system.

The qualified baseline is `developer-preview-v02`, source commit
`4bf8db6469a00dac69d2ddd7d103b501f797d7f6`, with candidate archive SHA-256
`ebc61a5ae235815456831934e4e4a31352591c2dc71044de1b5a64b3186b4282`.
All subsequent claims must preserve or explicitly replace that identity.

## Program architecture

Months 7–12 are evidence gates rather than calendar promises. Each month
consumes one exact accepted input, writes private qualification evidence, and
returns `PASS`, `REPAIR`, or `HOLD`:

- `PASS` advances to the next month.
- `REPAIR` permits only changes tied to demonstrated failures. It creates a new
  immutable candidate and reruns every invalidated gate.
- `HOLD` is reserved for a genuine external blocker that cannot be resolved
  safely within the task.

Months 7 and 8 form the first execution handoff. A Month 7 `PASS`
automatically starts Month 8. Months 9–12 remain planned but inactive until
Month 8 returns `ADVANCE`.

AO Mission records objectives, checkpoints, evidence digests, and final
reconciliation. It does not execute work, approve policy, call providers, or
grant publication authority. Repository changes remain test-driven and
ordinary GitHub release creation remains an explicitly authorized operator
action.

## Scope boundaries

The program keeps:

- the coherent eight-component AO Stack Windows baseline;
- five isolated AO2 office runtimes;
- exact-byte manifests, provenance, SBOM, checksums, and qualification records;
- private GitHub repository and release visibility;
- native NTFS qualification and fail-closed identity enforcement.

The program removes or defers:

- public `v1.2.0` publication;
- macOS and Linux development or qualification;
- Pulse or RSI product expansion;
- activation of AO components without an AO Office Pool requirement;
- schedulers, background services, cloud tenancy, public APIs, automatic
  updates, and elaborate CI/CD;
- skill-package redesign unless a demonstrated operator defect requires it.

## Month 7: private preview soak

### Inputs

Month 7 consumes the exact `developer-preview-v02` release assets. Preflight
must authenticate the private repository, redownload all eight uploaded
assets, and match their names, sizes, and SHA-256 values to the accepted
candidate manifest. A mismatch returns `HOLD`; it must not silently rebuild or
substitute bytes.

### Workload

Run a native Windows NTFS soak with all five offices. The gate requires both:

- at least 100 successful claim, resume, and release lifecycles distributed
  across O1–O5; and
- at least eight elapsed hours of mixed workload, including fresh-process
  restart and resume operations.

The workload uses disposable test projects and must cover concurrent claims,
same-task resume, clean release, failure recovery, repeated verification, and
bounded support readback. It records per-office operation counts, failures,
process exits, handle and resource trends, state digests, and residue results.
It never records receipts, prompts, credentials, private task content, or raw
support data in tracked files.

### Exit gate

Month 7 passes only when:

- all 100 or more lifecycles complete without duplicate ownership or
  cross-office access;
- restart and resume preserve the exact office, project, generation, and
  receipt authority;
- no unexplained monotonic handle, process, or storage growth remains;
- post-soak verification passes against unchanged installed bytes;
- uninstall leaves no candidate-owned residue and unknown residue is preserved
  and reported rather than deleted;
- the full Windows test suite passes against the exact source candidate; and
- AO Mission imports the evidence and reconciles the Month 7 gate.

A demonstrated product failure enters `REPAIR`. The executor writes a focused
failing test, makes the smallest correction, builds a new versioned candidate,
and reruns the full suite and entire Month 7 gate. A passing baseline advances
automatically to Month 8.

## Month 8: installer and lifecycle hardening

### Inputs

Month 8 consumes the exact Month 7 `PASS` candidate. If Month 7 required no
repair, this remains `developer-preview-v02`. Candidate identity may change
only through a versioned repair with new manifest, provenance, SBOM, and
checksums.

### Lifecycle matrix

On a fixed local NTFS volume, exercise:

- clean install, verification, uninstall, and reinstall;
- repeated nonmutating verification;
- rejection of corrupt, missing, substituted, or mismatched files;
- interruption and recovery at installer-controlled transaction boundaries;
- safe repair or reinstall from the exact accepted archive;
- component identity and help routes for all eight installed AO components;
- support-bundle and operator-diagnostic allowlists; and
- final cleanup with no candidate-owned residue.

Real cross-version update and rollback are required only when two independently
qualified candidates exist. The executor must not fabricate a second release
or weaken version checks merely to exercise that path. When only one qualified
candidate exists, deterministic update and rollback tests remain required and
the native two-version exercise moves to the stable-candidate qualification
gate in Month 11.

### Exit gate

Month 8 returns `ADVANCE` only when:

- every lifecycle-matrix operation has an exact expected state and passes;
- corruption and identity drift fail closed with bounded diagnostics;
- interrupted transitions converge to an accepted prior state or an explicit
  recovery-required state;
- support output contains no secrets, receipts, identities, local paths,
  private history, or raw support content;
- operator documentation matches the exercised commands and outcomes;
- focused regressions and the full Windows suite pass; and
- AO Mission reconciles with no ready node or unresolved blocker.

`REPAIR` follows the same failing-test, minimal-correction, immutable-candidate,
and invalidated-gate rerun rule as Month 7. `HOLD` requires an exact external
blocker and next action.

## Months 9–12

### Month 9: Windows security and boundary audit

Complete the threat model, security policy, ACL and path-identity adversarial
tests, dependency and SBOM audit, support-output inspection, and private
vulnerability-reporting procedure. The gate has no unresolved release blocker.

### Month 10: endurance and fault injection

Run longer five-office concurrency plus process-kill, storage-pressure,
transaction-interruption, recovery, reparse-point, and antivirus scenarios.
Start with a 24-hour run. Extend to 72 hours only when the 24-hour evidence or a
release requirement justifies the added elapsed time.

### Month 11: stable-candidate qualification

Freeze one immutable stable candidate and qualify it on clean Windows hosts.
Require two complete runs against identical bytes, with at least one run
independent of the primary implementation session. Exercise native
version-to-version update and rollback when a prior qualified candidate exists.
Any candidate change invalidates the affected qualification.

### Month 12: private stable release and stabilization

Publish only the exact qualified bytes to the private GitHub repository after
explicit operator authorization. Authenticated-redownload every uploaded asset
and verify exact names, sizes, and hashes. Hold a bounded stabilization window
for defect corrections only; do not add architecture during stabilization.

## Evidence and privacy

Tracked documentation contains contracts and sanitized summaries only. Raw
soak logs, release credentials, receipts, live office state, support bundles,
and AO Mission state remain under ignored private roots. Every gate summary
binds:

- source commit and clean-tree state;
- component lock and candidate manifest digests;
- exact release asset identity when applicable;
- test and qualification command results;
- cleanup and residue disposition;
- AO Mission checkpoint and reconciliation digests; and
- the resulting `PASS`, `REPAIR`, `HOLD`, or `ADVANCE` decision.

Unknown residue is never recursively removed. The executor resolves and
validates task-owned paths before cleanup and reports what was removed and
whether it contained data.

## Documentation and execution artifacts

Implementation will:

1. replace `docs/ROADMAP_MONTHS_7_12.md` with the Windows-private gated roadmap;
2. update the Months 1–6 roadmap transition text so it no longer promises a
   public release;
3. add an implementation plan under `docs/superpowers/plans/`;
4. create the ignored private handoff
   `.local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_WINDOWS_PRIVATE_HANDOFF.md`;
5. verify tracked documentation for stale public, cross-platform, private-path,
   and unsafe-authority wording; and
6. commit only the tracked design and roadmap documents.

The Month 7–8 executor creates its own goal, checks for orphan processes and
stale task-owned state, preserves unrelated work, and continues proactively
through Month 8 after a Month 7 `PASS`. It does not request permission merely
to continue already authorized in-scope work.
