# AO Office Pool Folder and Stack Layout

## AO Mission launch point

Run AO Mission with the connected-project working directory set to the AO
Office Pool repository root. Supply `.local/handoffs/AO_MISSION_HANDOFF.md` as
the handoff prompt. Do not run the mission from the AO Mission source checkout.

AO Mission writes durable records under `.ao/mission/`. The `.ao/` and `.local/`
trees stay outside Git.

Always pass the state root explicitly:

```sh
.local/bin/ao-mission --home .ao/mission init
.local/bin/ao-mission --home .ao/mission start "Build AO Office Pool through the months 1-6 developer-preview gate"
```

AO Mission records the objective; the LLM agent reads the Markdown handoff.

On macOS, ExFAT writes extended attributes as `._*` AppleDouble files. Use an
APFS scratch checkout for write-heavy tests and remove those metadata files
from `.ao/mission/` before mission enumeration. Windows qualification still
requires the fixed NTFS installation root.

## Public repository

```text
ao-office-pool/
├── .github/workflows/              CI definitions
├── cmd/                            user-facing command entrypoints
├── internal/                       coordination implementation
├── schemas/                        public JSON contracts
├── skills/                         seven portable product skills
├── scripts/                        deterministic build and verification tools
├── tests/                          portable and Windows-gated tests
├── manifests/
│   └── stack-layout.json           machine-readable placement contract
├── packaging/windows/              PowerShell packaging entrypoints
├── docs/                           public design and operating documents
├── .local/                         ignored local sources and staging
└── .ao/                            ignored connected-project mission state
```

The repository does not vendor AO source checkouts or generated runtime state.
`manifests/public-tree.json` is the machine-readable GitHub publication
boundary. `.gitignore` excludes every local or generated root in that contract.

## Ignored development sources

```text
.local/
├── sources/
│   ├── ao-architecture/            contract and compatibility reference
│   ├── ao-mission/
│   ├── ao2/
│   ├── ao2-control-plane/
│   ├── ao-blueprint/
│   ├── ao-atlas/
│   ├── ao-foundry/
│   ├── ao-forge/
│   ├── ao-covenant/
│   ├── ao-command/
│   ├── ao-arena/
│   ├── ao-crucible/
│   ├── ao-sentinel/
│   └── ao-promoter/
├── downloads/                      unverified downloaded assets
├── cache/                          rebuildable local cache
├── staging/windows-x86_64/         generated Windows package tree
├── handoffs/                       AO Mission prompts
└── drafts/                         private policy drafts
```

Task 1 verifies source identities before any checkout or asset enters an
accepted component lock. An empty component source directory does not establish
source presence, acceptance, or executable readiness.

## Windows staging and installation

The staging tree mirrors the final fixed NTFS installation root:

```text
<installation-root>\
├── bin\
├── components\
│   ├── ao-mission\<version>\
│   ├── ao2\<version>\              accepted package source
│   ├── ao2-control-plane\<version>\
│   ├── ao-blueprint\<version>\
│   ├── ao-atlas\<version>\
│   ├── ao-foundry\<version>\
│   ├── ao-forge\<version>\
│   ├── ao-covenant\<version>\
│   ├── ao-command\<version>\
│   ├── ao-arena\<version>\
│   ├── ao-crucible\<version>\
│   ├── ao-sentinel\<version>\
│   └── ao-promoter\<version>\
├── manifests\
├── pool.json                        generated after initialization
├── offices\
│   ├── O1\
│   │   ├── office-state.json        generated after initialization
│   │   ├── runtime\versions\<ao2-version>\
│   │   ├── history\
│   │   └── work\
│   ├── O2\                          same internal layout as O1
│   ├── O3\
│   ├── O4\
│   └── O5\
├── operator-secrets\
├── updates\
└── support-bundles\
```

AO components use shared immutable version directories. AO2 also receives five
independent, byte-identical runtime copies, one under each office. A runtime
version directory appears only after its package identity and files pass Task 1
verification. The scaffold does not create fake `pool.json`, office state,
receipts, manifests, or qualification records.

AO Architecture stays in the ignored development source tree as guidance and
contract evidence. It enters `components\` only if a later versioned lock
identifies a qualified runtime asset with a real executable role.

## Connected-project state

```text
<connected-project>/.ao/
├── mission/
├── workgraphs/
├── checkpoints/
└── evidence/
```

Project objectives, mission state, workgraphs, checkpoints, evidence, and
deliverables remain with the connected project. Offices contain transient
coordination and runtime state only.

## Placement rules

- `.local/sources/` contains development checkouts, never accepted runtime
  claims by itself.
- `.local/downloads/` contains unverified assets.
- `.local/staging/windows-x86_64/` mirrors package placement without making a
  Windows qualification claim.
- `components/` in the Windows tree contains shared immutable accepted packages.
- `offices/O1` through `offices/O5` contain independent AO2 runtime copies and
  private transient state.
- `.ao/` belongs to the connected project and survives office release.
- Git and release archives exclude `.local/`, `.ao/`, generated office state,
  secrets, prompts, receipts, and raw support data.
