# Task 6 Pool-Private Governance Witness Design

**Status:** Approved design; implementation requires a separate approved plan  
**Applies to:** Task 6, Planning routes and governed AO2 execution  
**Base commit:** `5af397240092f5b5f17f732fd6005e2e3e024035`

## Decision

AO Office Pool will use an automatic Pool-private governance witness. A receipt
holder cannot authorize execution by constructing Blueprint, Atlas, Forge, or
Covenant records. Office Pool must verify outputs from the exact locked producer
binaries, bind their relationships into one closed envelope, and authenticate
that envelope with a witness key that is never returned through a public API.

The witness is automatic after validation. It does not add an operator approval
to each execution. It does not call providers, publish, deploy, mutate an
upstream repository, or advance Production state.

## Why Task 6 Needs This Boundary

The upstream components expose useful contracts but no common signed chain:

- Blueprint emits `ao.blueprint.build-authorization.v0.1`.
- Atlas validates `ao.atlas.workgraph.v0.1` and related workgraph records.
- Forge emits factory packets, GoalRun state, evidence, and provenance records.
- Covenant emits policy decisions and `covenant.approval-ticket.v1` tickets.

These records can carry digests and cross-references, but a caller can reproduce
an unkeyed digest. The original Task 6 implementation accepted caller-created,
self-consistent dataclasses, which proved consistency rather than authority.
Receipt-keyed HMAC would have the same defect because the receipt holder knows
the key material. A distinct Pool-private witness key is therefore required.

## Trust Model

The witness trusts:

1. the Pool root and protected storage identity established by Tasks 3 and 4;
2. the active receipt, office, generation, and connected-project identity;
3. the authenticated Mission record established by Task 5;
4. component identities from the applicable locked platform manifest; and
5. outputs produced or validated by the exact opened locked binaries during the
   witness operation.

The witness does not trust caller-supplied route decisions, evidence digests,
producer names, executable paths, target paths, or prior unsealed records.

The witness key protects the application boundary. It lives in Pool-private
operator storage with restrictive native permissions, separate from recovery
keys and receipts. The private Windows developer preview verifies file identity,
non-disclosure, and restrictive permissions. Installer-grade ACL ownership is a
Task 8 qualification responsibility.

## Components

### Governance witness

`internal/governance_witness.py` owns producer invocation, artifact validation,
relationship checks, envelope creation, one-use consumption, and HMAC handling.
It exposes no raw-key or caller-selectable sealing primitive.

The implementation adds one closed governance-envelope schema. Producer-native
records remain byte-for-byte evidence; the envelope stores their digests and
the verified producer identities rather than copying arbitrary producer fields.

### Mission route binding

The authenticated Task 5 Mission record gains `current_route`. Task 5 persists
that value only from the exact verified Mission readback. Planning reconstructs
`MissionReadback` from the authenticated durable record and computes the route
with the fixed rule table. Execution does not accept a caller-selected Mission
readback or route decision as authority.

### Pool authority lease

Task 4 gains a private context-managed authority lease. It holds the Pool lock,
the validated receipt authority, and the retained connected-project identity
through witness consumption, AO2 launch, execution, and final record creation.
Release, recovery, or reclaim cannot race an accepted execution. The global
Pool lock is acceptable for the bounded 30-second Task 6 execution window.

### Governed executor

`internal/execution.py` consumes a private receipt path and a one-use governance
envelope path. It reconstructs all other authority from authenticated state.
It does not accept caller-created Blueprint, Atlas, Forge, Covenant, Mission, or
route objects as execution authority.

## Witness Key Lifecycle

Pool initialization creates one random 256-bit witness key in protected
operator storage. Creation is atomic and refuses to overwrite existing bytes.
The key file is physically contained under the Pool root, rejects links and
reparse points, and uses restrictive native permissions. Corrupt, missing, or
unexpected key bytes put governance into recovery-required state; they never
trigger silent key rotation.

The key is distinct from:

- receipt authority bytes;
- emergency recovery keys;
- Mission-record HMAC material; and
- executable or artifact hashes.

No public status, execution record, support record, exception, or log contains
the key or a reusable derivative.

## Governance Envelope

Each envelope is a closed, versioned JSON object with a detached HMAC. It binds:

- a fresh 128-bit-or-larger witness ID and one-use state;
- receipt-authority digest, office ID, generation, and runtime version;
- retained project physical identity and canonical project path;
- Mission ID, objective digest, authenticated Mission status, and current route;
- the fixed route decision and whether Atlas is required;
- task, request, target, workflow-byte, and run-ID digests;
- exact Blueprint, Atlas when required, Forge, and Covenant artifact digests;
- exact producer component names, commits, platform asset digests, and verified
  command contracts;
- Covenant decision, scope, expiry, and revocation state;
- B01-B19 and inherited-requirement evidence-set digest;
- creation time and a short bounded expiry; and
- the expected locked AO2 component identity.

An envelope is stored under the connected project’s protected `.ao` tree. Its
HMAC is keyed by the Pool-private witness key. The envelope never contains the
key, receipt bytes, recovery material, owner identity, prompt text, or raw
producer output.

Envelope consumption is atomic and one-use. A consumed, expired, revoked,
missing, malformed, relocated, or HMAC-invalid envelope stops before launch.
Replaying the same envelope cannot start AO2 twice.

## Producer Verification Flow

The caller supplies paths to candidate producer-native artifacts, not authority
objects. Office Pool performs the following operation while holding the Pool
authority lease:

1. Load the authenticated Mission record and compute the fixed route.
2. Open the retained project root and candidate artifacts without following
   links. Require every artifact to remain physically inside the project `.ao`
   evidence roots assigned to its producer.
3. Resolve each producer through the applicable locked platform manifest. Open
   and verify the executable identity through launch.
4. Invoke the producer’s validation or inspection command with an argument
   array, retained project cwd, closed stdin, live output bounds, and a timeout.
5. Validate the producer-native record against its exact supported contract.
6. Verify producer-to-producer relationships: Mission, objective, project,
   Blueprint authorization, Atlas workgraph when routed, Forge packet/workflow,
   Covenant decision, target, run ID, AO2 identity, and requirements evidence.
7. Reject denied, pending, stale, expired, revoked, source-only, wrong-route,
   contradictory, or extra evidence.
8. Persist the producer bytes unchanged, then create and HMAC-seal the common
   envelope from their verified digests and identities.

Deterministic fake producer executables in tests use the same CLI and output
contracts. Test helpers may build candidate native records, but cannot call a
production sealing function with arbitrary fields.

## Exact AO2 Launch

Execution uses the Task 5 verified-launch patterns:

- Linux executes the retained verified AO2 object through an inherited FD.
- macOS starts suspended, binds the loaded Mach-O vnode and cwd vnode to the
  retained verified objects, and resumes only after unambiguous verification.
- Windows retains no-write/no-delete-share handles through process creation.

The connected project is the retained cwd. AO2 receives `--target .`, so it
does not reopen a replaceable absolute target path.

The workflow is opened without following links and copied into protected
private staging. The copy and source descriptors must have identical hashes.
Linux and macOS pass a retained descriptor path for workflow reads; Windows
holds a no-write/no-delete-share workflow handle through process creation.

POSIX starts AO2 in a new session and kills/reaps the entire process group on
timeout, oversized output, or error. Windows assigns AO2 to a Job Object before
it may execute useful work; termination closes the whole job tree. AO2 cannot
leave a descendant running after Office Pool reports failure.

## Execution Records

Every attempt receives a full 128-bit-or-larger execution ID. Record creation
uses create-only semantics and retries a collision with a fresh ID. Existing
bytes are never replaced.

Before durable write, production validates the complete phase-specific record
against the closed execution schema. It writes atomically, reads the exact bytes
back through the retained project handle, validates again, and verifies the
record digest. Malformed AO2 output, valid non-object JSON, wrong evidence
types, timeouts, and process-tree failures all produce a controlled failure
record when authority still permits the write.

The public result remains a minimal allowlisted projection. Diagnostics contain
only fixed codes, counts, sizes, and digests.

## Failure Rules

The operation stops before witness creation or AO2 launch on any identity,
schema, relationship, route, expiry, revocation, containment, executable, or
artifact mismatch. No automatic fallback accepts an older artifact or another
route.

After AO2 starts, timeout or output overflow terminates the complete process
tree before failure is recorded. If durable record validation or readback fails,
the original bytes are preserved and the operation returns recovery-required.

## Verification

Local and native-Windows tests must cover:

- caller-forged producer records and self-consistent digest chains;
- wrong producer binary, commit, platform asset, or output contract;
- Mission route and durable-record tampering;
- envelope HMAC forgery, relocation, replay, expiry, and revocation;
- missing or unexpected Atlas evidence for the fixed route;
- B01-B19 evidence-set drift;
- receipt release/reclaim attempts during witness and execution;
- AO2 executable, target, cwd, and workflow substitutions at every boundary;
- timeout and oversized-output descendants that attempt to survive;
- malformed scalar/list AO2 output and wrong evidence types;
- execution-ID collision and pre-existing record bytes;
- witness-key corruption, overwrite attempts, disclosure scans, and path links;
- macOS loaded-vnode verification; and
- Windows NTFS junction, reparse, hard-link, delete/recreate, Job Object, and
  native locked-AO2 smoke behavior.

The final Task 6 gate reruns focused and full suites on macOS and Windows,
scans a clean allowlisted release source and archive, and retains exact package,
binary, producer, result, and cleanup hashes.

## Scope

This design amends Task 6 only. It may make narrow Task 4 and Task 5 interface
changes for the witness key, authority lease, and authenticated route field.
It does not implement Task 7 runtime activation, Task 8 packaging/installer
ACLs, a public release, provider calls, deployment, upstream source changes, or
Months 7-12 work.
