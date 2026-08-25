# Windows Stable Release Closure Design

## Purpose

AO Office Pool needs one bounded Windows-only program that converts the current
source-qualified repository into a genuinely qualified private stable-release
candidate. The program starts from repository commit
`892538bb05a9578db62bd7d46f1f8c2ce8427fd4` or a later explicitly accepted
successor, investigates the cumulative-suite slowdown, qualifies source with a
working compiler, assembles the real AO Stack, exercises an installed
five-office product, runs an eight-hour endurance campaign, and returns an
independently auditable release-readiness handback.

The program does not publish a GitHub release. Publication remains a separate
operator-authorized action after review of the final handback.

## Scope and success boundary

Windows x86-64 is the only supported platform. macOS, Linux, WSL, public
distribution, complex CI/CD, unrelated AO Stack development, and new product
architecture are outside scope.

Success means one immutable candidate has passed both source qualification and
installed-product qualification on fixed local NTFS, including real AO2, AO
Mission, AO Blueprint, the shipped product skills, and every declared
accessory. A source-only pass, a suite with compiler-dependent skips, or tests
against fake component binaries cannot produce release readiness.

The executor may install the documented Visual Studio Build Tools C++ workload
on the designated engineering host, use existing private-release credentials
without exposing them, create task branches, repair demonstrated defects,
build immutable private candidates, and write ignored private evidence. It may
not publish, change repository visibility, mutate `main` directly, broaden
platform scope, or replace missing verified binaries with locally invented
substitutes.

## Execution architecture

One capable Windows Codex task owns the program end to end. It creates a Goal,
uses an isolated source worktree, stores raw evidence under ignored
repository-local paths, and uses a unique qualification child on a fixed local
NTFS volume for mutable installed state. Durable checkpoints make the task
resumable across process restarts or context compaction without changing
candidate identity.

Each gate returns one of three decisions:

- `PASS`: the gate completed against its exact accepted inputs; continue.
- `REPAIR`: a demonstrated defect has a focused RED, the smallest correction,
  and a defined set of invalidated gates to rerun.
- `HOLD`: a genuine external blocker remains after safe in-scope alternatives
  are exhausted; record exact evidence and the next action.

Any change to source, component bytes, component lock, archive, installer,
manifest, provenance, SBOM, or checksums creates a new candidate and invalidates
every dependent result. Harness-only corrections do not change candidate
identity unless they change shipped bytes.

## Gate G0: identity and environment preflight

Resolve the repository and all task paths rather than hardcoding a developer
workspace. Freeze the accepted source commit, require a clean tracked tree,
record the private origin identity, create the Goal and private evidence root,
and inspect existing processes before ending only processes proven to belong
to this task.

Record Windows version, architecture, PowerShell and Python versions, volume
type and health, compiler status, link-creation capability, private-release
credential availability, and candidate/component availability. Mutable
qualification state must be on fixed local NTFS and outside release or source
trees. Unknown residue is preserved and reported.

## Gate G1: cumulative-suite stall investigation

The observed behavior is the starting evidence, not a presumed product bug:
the complete 438-test suite reached test 250, then
`test_interrupted_release_retries_directly_with_original_receipt_path` ran for
more than twenty minutes after pressure, while that test passed alone in
63.508 seconds and three concurrent 24-test crash suites had each completed in
approximately 741 seconds.

Add or adapt a reusable Windows test runner that records, for every test:

- stable test identity, start/end time, duration, and outcome;
- process tree and exit state;
- handle count, working set, private bytes, and task-root storage samples;
- bounded stdout/stderr diagnostics; and
- timeout, cleanup, and residue disposition.

Reproduce progressively: the isolated test, its immediately preceding tests,
the crash suite, the suite prefix through test 251, and the complete suite.
Use systematic debugging to distinguish harness buffering, test-order state,
resource exhaustion, orphan-process interference, antivirus/storage effects,
and an actual lifecycle defect. A timeout must fail with the current test
identity and actionable diagnostics rather than hang silently.

`PASS` requires either a reproduced and corrected cause or evidence that the
instrumented complete suite repeatedly finishes within an explicit recorded
baseline. A confirmed product defect enters the candidate-invalidating repair
loop. An instrument-only correction remains a harness change.

## Gate G2: compiler-complete source qualification

Run the documented compiler preflight. If the official Visual Studio Build
Tools C++ workload is absent on the designated engineering host, install it or
configure a verified `AO_TEST_VCVARS64` path, then rerun from a fresh process.

Require:

- `windows-c-compiler=ready`;
- zero compiler-dependent skips;
- the targeted repair and qualification suites passing;
- the complete instrumented Windows suite passing;
- every shipped schema and manifest parsing;
- every shipped PowerShell script parsing;
- bootstrap contract verification;
- public-tree scan with zero findings; and
- clean `git diff --check` and tracked status.

Privilege-dependent reparse/link tests must execute at least once on a
Developer Mode or appropriately privileged Windows host. Remaining skips must
be classified against an explicit Windows-only allowlist; raw skip count alone
is not acceptance evidence.

## Gate G3: checksum-bound private candidate

Acquire the verified latest Windows AO Stack components from their authoritative
private releases or accepted build outputs. The candidate must include real
AO2, AO Mission, AO Blueprint, all declared accessories, and the required
product skills. Record exact source commits, release tags, asset names, sizes,
and SHA-256 values before assembly.

Build one immutable candidate and bind:

- AO Office Pool source commit and clean-tree state;
- component lock and all component identities;
- archive identity and complete member inventory;
- candidate manifest, provenance, SBOM, licenses, and checksum set; and
- installer/uninstaller identities and supported Windows architecture.

Build twice from identical inputs and require byte-for-byte deterministic
output. Scan both extracted trees and compare complete inventories. Store
candidates and raw evidence privately. Do not upload or publish the candidate.

## Gate G4: real installed-product qualification

Install the accepted candidate into a new empty fixed-local-NTFS qualification
root that represents an ordinary customer host. Visual Studio is not a runtime
prerequisite for this gate.

Exercise all five offices and every shipped component and skill through the
documented operator surface. Cover clean install, identity/help, claim, exact
resume, real task execution, release, recovery, corruption rejection, repair,
reinstall, update and rollback where two qualified candidates exist, support
output, uninstall, and zero candidate-owned residue. Verify isolation across
office, owner, project, generation, and receipt boundaries.

Fake runtimes, mocked component outputs, and source-tree substitution do not
satisfy this gate. If authenticated release acquisition or any required binary
is unavailable, return `HOLD` with its exact missing identity.

## Gate G5: eight-hour installed endurance campaign

Use the reusable endurance runner against the unchanged installed candidate.
Run for at least eight elapsed hours with work distributed across the interval,
not an initial burst followed by idle time. Complete at least 100 successful
claim/resume/execute/release lifecycles, with at least 20 per office.

Mix normal work with allocation races, fresh-process resumes, controlled
process termination, recovery, update/rollback when valid inputs exist,
repeated verification, diagnostics generation, and cleanup. Sample resources
at least every five minutes and record hourly summaries. Define latency and
throughput baselines from the campaign and fail on unexplained monotonic
process, handle, memory, or storage growth.

After the workload, require all offices free, exact installed-byte verification,
the instrumented source regression suite, uninstall, process cleanup, and zero
candidate-owned residue. Unknown residue remains preserved and classified.

## Gate G6: final audit and release-readiness handback

Recheck source identity, component lock, archive, inventory, manifests,
provenance, SBOM, checksums, privacy scanner, schema parsing, PowerShell parsing,
installed-product results, endurance evidence, and cleanup. AO Mission imports
checkpoint digests and reconciles the final objective without gaining execution
or publication authority.

Write an ignored private handback that includes exact commands, counts,
durations, skips and their classifications, exit codes, candidate identities,
repair commits, resource trends, residue disposition, AO Mission checkpoint
digests, and one terminal recommendation:

- `RELEASE_READY`: every gate passed; request independent final audit and
  explicit publication authorization.
- `REPAIR`: a demonstrated defect remains in the active repair loop.
- `HOLD`: an external prerequisite remains unavailable with an exact next
  action.

Do not publish from this handoff.

## Schedule and uncertainty

| Work | Active effort | Calendar time |
|---|---:|---:|
| Instrument and reproduce cumulative-suite stall | 0.5–2 days | 1–3 days |
| Fix any confirmed order/state leak | 0.5–5 days | uncertain |
| Install compiler and complete source qualification | 2–6 hours | 1 day |
| Assemble checksum-bound private candidate | 0.5–1 day | 1–2 days |
| Install and test real AO2/Mission/Blueprint stack | 1–2 days | 1–3 days |
| Add or adapt endurance runner | 1–3 days | 2–4 days |
| Run eight-hour endurance campaign and analyze evidence | 1 day | 1 day |
| Final privacy, manifest, archive, and release-readiness audit | 0.5–1 day | 1 day |

The optimistic schedule is 4–6 working days. The likely schedule is one to two
weeks. Allow two to four weeks when component binaries are unavailable or the
cumulative slowdown exposes a product defect. The planning commitment is two
weeks with an evidence-backed extension rather than a weakened gate.

The main uncertainties are whether the slowdown is harness/order behavior or a
real lifecycle defect, and whether authoritative AO2, AO Mission, Blueprint,
accessory binaries, and release metadata are immediately available.

## Documentation artifacts

Implementation of this design will:

1. update `docs/ROADMAP_MONTHS_7_12.md` to use gates G0–G6 as the immediate
   release-closure program while retaining Months 9–12 as later hardening;
2. add a detailed implementation plan under `docs/superpowers/plans/`;
3. create the ignored private handoff
   `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md`;
4. require the executor to return
   `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDBACK.md`; and
5. keep publication as a separately authorized final audit and action.
