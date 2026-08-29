# AO Office Pool Roadmap: Windows Stable Release Closure

This roadmap advances AO Office Pool from its current Windows source baseline
to an independently auditable private stable-release candidate. Windows x86-64
is the only supported platform. The repository and candidate evidence remain
private, delivery remains manual and evidence-gated, and complex CI/CD is not
required.

The accepted source starting point is
`892538bb05a9578db62bd7d46f1f8c2ce8427fd4`. A later successor may replace it
only after its full commit identity and clean tracked-tree state are recorded at
Gate G0. No release archive is accepted at the start of this program. Gate G3
creates and binds the first candidate from verified real component inputs.

Gates G0–G6 are the immediate release-closure program. They produce a
checksum-bound candidate and a private `RELEASE_READY`, `REPAIR`, or `HOLD`
handback. They do not publish a GitHub release. Publication remains a separate
operator-authorized action after independent review of the handback.

## Program rules

- Run native qualification on Windows x86-64 and fixed local NTFS.
- Use one capable Windows Codex task with a Goal and durable private
  checkpoints through G0–G6.
- Keep source, candidates, downloads, logs, AO Mission state, credentials,
  receipts, support bundles, and raw evidence private and ignored where
  appropriate.
- Keep every candidate immutable and bind source, component lock, archive,
  inventory, manifest, provenance, SBOM, licenses, checksums, and evidence by
  exact digest.
- Preserve five isolated AO2 offices and every owner, project, generation,
  receipt, path, and component-identity boundary.
- Use AO Mission for objectives, checkpoints, evidence, and reconciliation
  only. AO Mission does not execute work, approve policy, call providers, or
  grant publication authority.
- Create a new candidate only for a demonstrated product or shipped-byte
  correction. A harness-only correction does not relabel product bytes.
- Preserve and classify unknown residue. Remove only task-owned paths after
  resolving and validating their exact identities.
- Treat each gate as `PASS`, `REPAIR`, or `HOLD`. `PASS` continues immediately;
  `REPAIR` permits the smallest demonstrated correction and reruns every
  invalidated gate; `HOLD` requires an external blocker and exact next action.
- Never weaken a gate, invent missing binaries, substitute fake runtimes, or
  accept compiler-dependent skips to meet a schedule.

## Gate G0: identity and environment preflight

Create the Goal, resolve the repository root with Git, record the accepted
source commit and clean-tree state, create an isolated task branch and source
worktree, and allocate ignored evidence state. Reconcile prior reports,
candidates, component sources, release metadata, credentials presence, running
processes, and task-owned residue before accepting any input.

Record Windows version and architecture, PowerShell and Python versions,
filesystem type and health, compiler state, link-creation capability,
private-release credential availability, and component availability. Mutable
installation and endurance state must use a unique child of an
operator-selected fixed local NTFS root and must not use a source worktree,
release tree, removable volume, network share, or WSL.

G0 `PASS` freezes exact source and environment identities. Missing credentials
or verified components may be recorded for later acquisition; an unsafe or
ambiguous workspace is `HOLD` until it is resolved.

## Gate G1: cumulative-suite stall investigation

The starting anomaly is specific: after pressure, the 438-test suite reached
test 250 and the next test,
`test_interrupted_release_retries_directly_with_original_receipt_path`, ran for
more than twenty minutes. The same test passed alone in 63.508 seconds, while
three concurrent complete crash suites had each finished in approximately 741
seconds. This is evidence of cumulative or order-sensitive degradation, not
proof of a product defect.

Add or adapt a reusable Windows regression runner that records per-test
identity, start and end time, duration, result, bounded output, process tree,
handle count, working set, private bytes, task-root storage, timeout evidence,
cleanup, and residue. A timeout must fail with the active test identity and
actionable diagnostics rather than hanging silently.

Reproduce in this order:

1. the isolated test;
2. its immediately preceding tests followed by the target;
3. the complete crash suite;
4. the discovered-suite prefix through the target; and
5. the complete Windows suite.

Investigate harness buffering, test-order state, resource exhaustion, orphan
processes, antivirus or storage effects, and lifecycle state. Use one focused
RED for a demonstrated cause and the smallest GREEN correction.

G1 `PASS` requires either a reproduced and corrected cause or repeated
instrumented complete-suite finishes within an explicitly recorded baseline.
A product correction invalidates downstream candidate evidence. A harness-only
correction reruns affected tests without changing candidate identity.

## Gate G2: compiler-complete Windows source qualification

Run the documented compiler preflight on the designated engineering host. If
the compiler is absent, install the official Visual Studio Build Tools Desktop
development with C++ workload or configure a verified `AO_TEST_VCVARS64` path,
then start a fresh shell and rerun preflight.

G2 requires:

- `windows-c-compiler=ready`;
- zero compiler-dependent skips;
- the targeted G1 repair and qualification suites passing;
- the complete instrumented Windows suite passing;
- all shipped schemas and manifests parsing;
- all shipped PowerShell scripts parsing;
- public-tree findings equal to zero;
- bootstrap verification reporting 13 members and 5 documents;
- privilege-dependent link and reparse cases executed at least once on a
  Developer Mode or appropriately privileged Windows host;
- every remaining skip classified against an explicit Windows-only allowlist;
  and
- clean `git diff --check` and tracked status.

Compiler-dependent skips are a stop signal even when `unittest` prints `OK`.
Visual Studio is an engineering-host prerequisite, not an installed-product
runtime prerequisite.

## Gate G3: checksum-bound real-stack candidate

Acquire the authoritative current Windows releases or accepted build outputs
for AO2, AO Mission, AO Blueprint, every declared accessory, and each required
product skill. Record exact repositories, commits, release tags, asset names,
sizes, and SHA-256 values. Missing verified bytes are `HOLD`; do not replace
them with locally invented, stale, fake, or source-substituted assets.

Build one immutable candidate and bind:

- AO Office Pool source commit and clean-tree state;
- component lock and all component identities;
- archive identity and complete member inventory;
- candidate manifest, provenance, SBOM, licenses, and checksum set; and
- installer, uninstaller, and supported Windows architecture identities.

Build twice from identical inputs. Require byte-for-byte equal archives,
identical extracted inventories, clean privacy scans on both extractions, and
schema-valid metadata. Store the candidate and raw evidence privately. Do not
upload or publish it.

## Gate G4: installed five-office product qualification

Install the accepted G3 candidate into a new empty fixed-local-NTFS customer-like
qualification root. The host must not need Visual Studio to install or operate
the product.

Using documented operator surfaces, exercise:

- clean install and exact verification;
- identity and help routes for AO2, AO Mission, AO Blueprint, every skill, and
  every declared accessory;
- five-office claim, exact resume, real task execution, clean release, and
  controlled recovery;
- wrong-owner, wrong-project, wrong-generation, wrong-receipt, and
  cross-office rejection;
- corruption, missing-file, substituted-file, and identity-drift rejection;
- repair, reinstall, repeated nonmutating verification, support output, and
  diagnostics;
- native update and rollback when two independently qualified candidates
  exist; and
- uninstall, process cleanup, and zero candidate-owned residue.

Fake runtimes, mocked component output, and source-tree substitution do not
satisfy G4. Unknown residue is preserved and classified rather than deleted.

## Gate G5: eight-hour installed endurance campaign

Run the reusable endurance runner against the unchanged installed candidate
for at least eight elapsed hours. Work must remain distributed throughout the
interval rather than completing early and idling.

Complete at least 100 successful claim, resume, real execute, and release
lifecycles, including at least 20 successful lifecycles per office. Mix normal
work with allocation races, same-task continuation, fresh-process resume,
controlled process termination, recovery, valid update/rollback when available,
repeated verification, diagnostics, and cleanup.

Sample at least every five minutes:

- elapsed time and per-office success/failure counts;
- operation latency and throughput;
- process count, exits, working set, private bytes, handles, and children;
- pool and office state digests;
- task-root storage and residue; and
- exact installed-byte verification.

Record hourly summaries and define observed latency and throughput baselines.
Unexplained monotonic process, handle, memory, or storage growth is `REPAIR`
unless bounded retesting disproves it. After the workload, require all offices
free, exact verification, the complete instrumented source suite, uninstall,
no task-owned process, and zero candidate-owned residue.

## Gate G6: final audit and private handback

Recheck source identity, component lock, candidate archive, inventory,
manifest, provenance, SBOM, licenses, checksums, privacy scan, schema and
PowerShell parsing, installed-product results, endurance results, and cleanup.
Import checkpoint digests into AO Mission and reconcile the objective without
granting AO Mission publication authority.

Write the private ignored handback
`.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDBACK.md` with exact
commands, test counts, durations, skip classifications, exits, identities,
repair commits, invalidated gates, resource trends, residue disposition,
checkpoint digests, and one terminal recommendation:

- `RELEASE_READY`: every G0–G6 gate passed; request independent final audit and
  explicit publication authorization.
- `REPAIR`: a demonstrated defect remains in the defined repair loop.
- `HOLD`: an external prerequisite is unavailable with exact evidence and next
  action.

G6 must state explicitly that publication did not occur.

## Effort and schedule

| Work | Active effort | Calendar time |
|---|---:|---:|
| Instrument and reproduce cumulative-suite stall | 0.5–2 days | 1–3 days |
| Fix any confirmed order/state leak | 0.5–5 days | uncertain |
| Install compiler and complete source qualification | 2–6 hours | 1 day |
| Assemble checksum-bound private release | 0.5–1 day | 1–2 days |
| Install and test real AO2/Mission/Blueprint stack | 1–2 days | 1–3 days |
| Add or adapt endurance runner | 1–3 days | 2–4 days |
| Run eight-hour endurance campaign and analyze evidence | 1 day | 1 day |
| Final privacy, manifest, archive, and private-release audit | 0.5–1 day | 1 day |

- Optimistic: 4–6 working days.
- Likely: 1–2 weeks.
- If binaries are missing or G1 exposes a real defect: 2–4 weeks.
- Planning commitment: two weeks with an evidence-backed extension rather than
  a weakened gate.

The two major uncertainties are whether the cumulative slowdown is a harness
or order issue versus a lifecycle defect, and whether authoritative AO2,
Mission, Blueprint, accessory binaries, and release metadata are immediately
available.

## Later hardening: Months 9–12

Months 9–12 remain inactive until G6 returns `RELEASE_READY` and an independent
audit accepts the handback.

### Month 9: Windows security and boundary audit

Complete the release threat model and security policy. Exercise ACL, handle
identity, junction, hard-link, symlink, 8.3, UNC, extended-path, and
delete/recreate boundaries. Audit dependencies, SBOM, support output, secrets,
receipts, and the private vulnerability-reporting procedure.

### Month 10: extended endurance and fault injection

Start with a 24-hour five-office run covering process termination,
storage-pressure, transaction interruption, recovery, reparse points, and
antivirus scenarios. Extend to 72 hours only when evidence or a release
requirement justifies it.

### Month 11: stable-candidate qualification

Freeze the accepted candidate and require two clean-host complete runs against
identical bytes, with at least one run independent of the implementation task.
Exercise native version-to-version update and rollback when a prior
independently qualified candidate exists.

### Month 12: private stable publication and stabilization

Only after explicit operator authorization, publish the exact independently
qualified bytes to the private GitHub repository. Authenticated-redownload
every uploaded asset and verify exact names, sizes, and hashes. Hold a bounded
stabilization window for defect corrections only; add no new architecture.

## Outside the program

macOS and Linux support, public distribution, WSL qualification, Pulse or RSI
expansion, unrelated skill redesign, schedulers, automatic queues, permanent
background services, cloud tenancy, public network APIs, unsolicited automatic
updates, and complex CI/CD are outside scope.
