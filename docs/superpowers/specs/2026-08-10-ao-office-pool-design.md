# AO Office Pool Design

Date: 2026-08-10
Status: approved direction for initial development planning

## Objective

AO Office Pool will provide five isolated Windows execution offices over one
shared, version-pinned AO orchestration stack. A project conversation claims or
resumes one office before governed execution. AO Mission records and routes the
objective; downstream AO components plan, authorize, execute, evaluate, and
report according to their existing authority boundaries.

The product targets local Windows operation. macOS and the WD1TB external drive
serve as a portable construction and staging environment. Windows qualification
must run from a fixed directory on a local NTFS volume.

## Product boundary

The product owns:

- atomic allocation of offices O1 through O5;
- private receipt-bound ownership and resume;
- connected-project binding and output-path enforcement;
- independent AO2 runtime copies for each office;
- shared immutable AO component packages and capability metadata;
- clean release, recovery, update, rollback, and public-safe status;
- Windows packaging, installation, verification, and qualification.

The connected project owns mission records, workgraphs, checkpoints, evidence,
and deliverables under its local `.ao/` state root. AO Office Pool must not use
an office as permanent project storage.

## End-state layout

The portable macOS staging repository contains public source and documentation:

```text
ao-office-pool/
├── .github/
├── cmd/
├── internal/
├── schemas/
├── scripts/
├── tests/
├── docs/
├── manifests/
├── packaging/
└── .local/                 ignored local handoffs and mission state
```

The finalized Windows installation adds generated state:

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

The installer chooses and records the fixed Windows root. Public source must
not hardcode a username or a developer's local path.

## AO workflow

```text
conversation
  -> claim or resume office
  -> AO Mission mission record and route decision
  -> AO Blueprint requirements and authorization when needed
  -> AO Atlas decomposition for oversized, mutation-class, or long work
  -> AO Foundry and AO Forge coordination
  -> AO Covenant authority decision
  -> AO2 bounded execution
  -> Arena, Crucible, Sentinel, and Promoter gates as required
  -> AO Command and Mission readback
  -> retain or release office
```

AO Mission is the prompt and continuation entrypoint. It does not receive
execution, provider, repository-mutation, release, or policy-approval authority.
AO2 remains the bounded execution runtime.

## Isolation model

The product shares immutable component binaries and source references. It does
not copy every AO repository into every office. Each office receives:

- a unique office identifier and generation;
- one active owner and connected-project binding;
- a private receipt stored outside public output;
- an independent byte-identical AO2 runtime copy;
- private transient execution state and protected history.

Project-specific AO state remains under `<connected-project>/.ao/`. Releasing an
office removes or closes transient ownership without deleting project evidence.
A sixth claimant receives a clear full-capacity result. The product does not
queue, steal, expire, or reassign active work automatically.

## Public and private data

Git may contain source, schemas, documentation, sanitized fixtures, public-safe
test evidence, checksums, SBOMs, and release metadata.

Git and public release archives must exclude:

- prompts, task descriptions, and raw transcripts;
- owner identifiers, receipts, recovery keys, and resume pointers;
- absolute developer or connected-project paths;
- live office state and private execution history;
- environment files, credentials, tokens, and private support bundles.

Release construction must use an allowlist. A release leak scan must reject
forbidden paths, known local path prefixes, private state filenames, and
secret-shaped values before publication.

## Windows requirements

Windows qualification must cover:

- native x86-64 executable identity and supported version commands;
- NTFS file identity, locking, ACLs, atomic replacement, and interruption;
- drive-letter, UNC, extended-path, 8.3 alias, case-folding, and separator rules;
- reserved device names, trailing spaces and periods, and invalid path segments;
- junction, reparse-point, hard-link, symlink, and traversal rejection;
- PowerShell installation, update, rollback, uninstall, and verification;
- Windows Defender-compatible packaging and process cleanup;
- path lengths at and beyond common Windows limits;
- five independent runtime copies with equal accepted bytes.

macOS tests may validate portable logic and manifests. They cannot establish
Windows file-identity, locking, ACL, native executable, or Production claims.

## Failure behavior

Security and ownership failures stop before execution. Unknown office residue is
preserved and marks the office recovery-required. Runtime activation requires
all five offices to be free. Failed staging or activation restores the previous
accepted runtime and writes a sanitized local diagnostic record. Public status
uses an explicit field allowlist.

## Verification strategy

Development proceeds through four gates:

1. portable unit and contract tests on macOS;
2. Windows CI for path, lock, packaging, and native executable behavior;
3. isolated five-office integration tests on a clean Windows host;
4. independent release qualification against the frozen source and package
   manifests.

Each nontrivial control receives one focused automated test before its
implementation. Release qualification includes a clean-room extraction and a
scan of the exact public archive.

## Deliberate exclusions

The initial release will not provide cloud tenancy, network-facing APIs,
automatic queues, hardware scheduling, autonomous credential use, direct-main
mutation, or five copies of every AO source repository. These features require
separate designs and threat models.
