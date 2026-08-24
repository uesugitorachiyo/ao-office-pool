# AO Office Pool Roadmap: Windows-Private Months 7–12

Months 7–12 advance the qualified Windows developer preview to a private stable
AO Office Pool release. Windows x86-64 is the only supported platform. The
repository and every release remain private. Delivery is manual and
evidence-gated; this program does not require complex CI/CD.

The months are gates, not mandatory calendar durations. Each gate consumes one
exact accepted candidate and returns `PASS`, `REPAIR`, or `HOLD`. Month 8 uses
`ADVANCE` for its terminal pass. `REPAIR` permits only changes tied to a
demonstrated failure and invalidates every affected result. `HOLD` is reserved
for a genuine external blocker with an exact next action.

The accepted starting point is `developer-preview-v02`, source commit
`4bf8db6469a00dac69d2ddd7d103b501f797d7f6`, archive SHA-256
`ebc61a5ae235815456831934e4e4a31352591c2dc71044de1b5a64b3186b4282`.

## Program rules

- Run native qualification on Windows and a fixed local NTFS volume.
- Keep source, candidates, logs, AO Mission state, and raw qualification
  evidence private and ignored where appropriate.
- Keep each candidate immutable and bind source, component lock, archive,
  manifest, provenance, SBOM, checksums, and evidence by exact digest.
- Preserve five isolated AO2 office runtimes and all AO authority boundaries.
- Use AO Mission for objectives, checkpoints, evidence, and reconciliation
  only. AO Mission does not execute work or grant publication authority.
- Create a new candidate only for a demonstrated correction. Never rebuild
  merely to refresh timestamps, exercise an upgrade, or change labels.
- Preserve unknown residue and report it. Remove only paths proven to belong to
  the active task after resolving their exact absolute identities.
- Month 7 `PASS` starts Month 8 automatically. Months 9–12 remain inactive
  until Month 8 returns `ADVANCE`.

## Month 7: Private preview soak

### Inputs and workload

Authenticate to the private repository, redownload all eight uploaded
`developer-preview-v02` assets, and match exact names, sizes, and SHA-256 values
before installation. A mismatch is `HOLD`; do not substitute or rebuild bytes.

Run all five offices on fixed local NTFS. The gate requires:

- at least 100 successful claim, resume, and release lifecycles distributed
  across O1–O5;
- at least eight hours of elapsed mixed workload;
- fresh-process restart and exact resume coverage;
- concurrent claim, same-task continuation, clean release, failure recovery,
  repeated verification, and bounded support readback;
- per-office operation counts, failure counts, process exits, resource trends,
  state digests, and residue results.

Use disposable test projects. Do not persist receipts, prompts, credentials,
private task content, or raw support data in tracked files.

### Exit gate

Month 7 returns `PASS` only when:

- every required lifecycle completes without duplicate ownership or
  cross-office access;
- restart and resume preserve exact office, project, generation, and receipt
  authority;
- no unexplained monotonic handle, process, or storage growth remains;
- post-soak verification passes against unchanged installed bytes;
- uninstall leaves zero candidate-owned residue;
- the complete Windows suite passes against the exact candidate source; and
- AO Mission imports the evidence and reconciles without a blocker.

`PASS` starts Month 8 automatically. `REPAIR` requires one focused failing
test, the smallest correction, a new immutable candidate, the full Windows
suite, and a complete Month 7 rerun from authenticated redownload. `HOLD`
requires an external blocker and exact next action.

## Month 8: Installer and lifecycle hardening

Month 8 consumes the exact Month 7 `PASS` candidate. If Month 7 required no
repair, the input remains `developer-preview-v02`.

### Lifecycle matrix

Exercise on fixed local NTFS:

- clean install, verification, uninstall, and reinstall;
- repeated nonmutating verification;
- rejection of corrupt, missing, substituted, or mismatched files;
- interruption and recovery at installer-controlled transaction boundaries;
- safe repair or reinstall from the exact accepted archive;
- identity and help routes for all eight installed AO components;
- support-bundle and operator-diagnostic allowlists; and
- final cleanup with zero candidate-owned residue.

Native version-to-version update and rollback require two independently
qualified candidates. Do not fabricate a second release or weaken version
checks to satisfy the test. When only one qualified candidate exists,
deterministic update and rollback tests remain required and the native
two-version exercise moves to Month 11.

### Exit gate

Month 8 returns `ADVANCE` only when:

- every lifecycle operation reaches its exact expected state;
- corruption and identity drift fail closed with bounded diagnostics;
- interrupted transitions converge to an accepted prior state or an explicit
  recovery-required state;
- support output contains no secrets, receipts, identities, local paths,
  private history, or raw support content;
- operator documentation matches the exercised commands and outcomes;
- focused regressions and the complete Windows suite pass;
- uninstall leaves zero candidate-owned residue; and
- AO Mission reconciles with no ready node or unresolved blocker.

`REPAIR` follows the Month 7 correction and invalidated-gate rerun rule.
`HOLD` requires a genuine external blocker and exact next action.

## Month 9: Windows security and boundary audit

Complete the release threat model and security policy. Exercise ACL, handle
identity, junction, hard-link, symlink, 8.3, UNC, extended-path, and
delete/recreate boundaries. Audit dependencies, SBOM, support outputs, secrets,
receipts, and the private vulnerability-reporting procedure.

The gate has no unresolved release blocker and no evaluator, diagnostic, or
readback surface can execute, publish, approve policy, or mutate accepted
state.

## Month 10: Endurance and fault injection

Run five-office concurrency plus process-kill, storage-pressure,
transaction-interruption, recovery, reparse-point, and antivirus scenarios.
Start with a 24-hour endurance run. Extend it to 72 hours only when the 24-hour
evidence or an explicit release requirement justifies the added elapsed time.

Every interruption must converge to accepted prior state or explicit
recovery-required state without duplicate ownership, cross-project access,
secret disclosure, or accepted-state corruption.

## Month 11: Stable-candidate qualification

Freeze one immutable stable candidate and qualify it on clean Windows hosts.
Require two clean-host, complete runs against identical bytes, with at least
one run independent of the primary implementation session. Exercise native
version-to-version update and rollback when a prior independently qualified
candidate exists.

Any source, component, archive, manifest, installer, or bound-evidence change
invalidates the affected qualification and requires a new candidate.

## Month 12: Private stable release and stabilization

After explicit operator authorization, publish only the exact independently
qualified bytes to the private GitHub repository. Authenticated-redownload
every uploaded asset and compare exact names, sizes, and hashes. Record the tag
target, release identity, qualification digests, and rollback decision.

Hold a bounded stabilization window for defect corrections only. Do not add
new architecture during stabilization.

## Outside the program

macOS and Linux support, public distribution, Pulse or RSI expansion,
unrelated skill-package redesign, activation of unused AO components,
schedulers, automatic queues, permanent background services, cloud tenancy,
public network APIs, unsolicited automatic updates, and complex CI/CD are
outside scope. A later requirement and threat model must justify any such
surface.
