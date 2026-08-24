# Windows AI-Operable Bootstrap Design

## Status and objective

This design defines the first of two Windows-only productization slices for AO
Office Pool. It turns the private developer preview into a release that a human
or an AI operator can discover, download, verify, install, inspect, recover, and
uninstall from a clean Windows directory without relying on machine-specific
repository knowledge.

The second slice, a user-facing office lifecycle command and standardized
endurance runner, remains explicitly separate. The bootstrap slice must pass
before lifecycle work begins because operational commands cannot be qualified
against an ambiguous installation contract.

The release remains private. This design does not authorize publication,
visibility changes, platform expansion, provider calls, or mutation of an
existing release.

## Confirmed defects

The current private archive contains the eight expected Windows executables,
but its onboarding surface is not an operable product contract:

- the shipped root `README.md` says no qualified Windows release exists;
- the operator guide assumes the operator already has the archive, checksum,
  and installer scripts and does not explain the clean-machine path;
- `cmd/` and `skills/` contain placeholders rather than product entry points;
- `scripts/build_preview.py` binds component discovery to one private absolute
  developer checkout path;
- `scripts/scan_public_tree.py` exits nonzero without printing findings;
- normal Python bytecode caches can therefore cause an unexplained failure;
- no acceptance test proves that the documented relative-path procedure works
  from a new directory.

The separate `ao2-Public Instance V1.2` pressure campaign is useful evidence
for coordination behavior, but it is not evidence about the contents of the
private AO Office Pool candidate. Bootstrap qualification must name and hash
the exact private release assets it uses.

## Design principles

### Relative-path contract

Tracked documentation, manifests, scripts, tests, and generated public or
protected artifacts must not contain developer-machine absolute paths.

Commands in onboarding documents start at either the repository root or the
download directory and use paths such as `./packaging/...`, `./downloads`, and
`./install`. PowerShell scripts locate package-owned files from `$PSScriptRoot`.
When Windows security requires a drive-absolute NTFS path, the operator supplies
or derives it at runtime and the script resolves and validates it; the value is
never committed as a product constant.

Examples may use variables such as `$ReleaseRoot`, `$DownloadRoot`, and
`$InstallRoot`, but must not contain a real user name, repository checkout, or
developer drive. The default install example derives a child from
`$env:LOCALAPPDATA`, then passes the resolved value to the existing fail-closed
installer.

### AI-operable instructions

Every operator step states:

1. prerequisites and required authority;
2. the exact command to run;
3. expected success output or observable files;
4. fail-closed conditions;
5. the next allowed step;
6. recovery or escalation behavior;
7. which values are secrets and must not be printed or persisted.

The runbook does not use implicit phrases such as “download the files,” “run
the installer,” or “verify normally.” An AI must be able to map every step to a
bounded command and decide `CONTINUE`, `REPAIR`, or `HOLD` from its output.

## Deliverables

### 1. Root onboarding surface

`README.md` becomes the truthful entry point for the private Windows product.
It identifies the current maturity, Windows x86-64 and local-NTFS boundary,
the eight-component stack, privacy constraints, and the supported bootstrap
and verification outcomes. It links only with repository-relative Markdown
paths.

`README-FIRST.md` is included at the archive root. It begins after authenticated
acquisition and archive-hash verification, contains the minimum relative
install/verify sequence, and links to `docs/QUICKSTART.md` and
`docs/AI_OPERATOR_RUNBOOK.md`. It never implies that an archive can authenticate
itself.

`docs/QUICKSTART.md` provides the shortest human path. It covers prerequisites,
private GitHub authentication, release selection, download, checksum and asset
verification, installation, verification, status inspection, recovery, and
uninstall.

`docs/AI_OPERATOR_RUNBOOK.md` is the normative automation contract. It uses
numbered gates, exact relative commands, expected fields, stop conditions, and
evidence filenames. It must explicitly state that successful installation does
not yet authorize actual office execution until the lifecycle slice is
qualified.

### 2. Authenticated private-release acquisition

`packaging/Get-AOOfficePoolRelease.ps1` downloads the exact assets described by
the two-level release authority into a caller-selected destination whose
default is `./downloads` relative to the invocation directory.

The tracked control-plane file `manifests/developer-preview-release.json` pins
the repository, private visibility, release tag, product-source commit,
architecture, exact closed release-asset names, and the external
`candidate-manifest.json` name, size, and SHA-256. The candidate manifest then
binds the archive, checksum sidecar, inventories, provenance, release notes,
SBOM, and checksum list. It does not list or hash itself. This existing
two-level pattern prevents an impossible self-referential archive or manifest
hash.

The exact control-plane release contract is excluded from the preview archive.
It is created only after deterministic candidate construction and belongs to a
later control commit. The archive records its product-source commit; the
control contract records both that source identity and the external candidate
manifest identity.

The script:

- accepts the GitHub repository and release tag only when they equal the
  control-plane contract;
- reads authentication from `GITHUB_TOKEN` without echoing or serializing it;
- requests repository and release metadata through the authenticated GitHub
  API;
- requires private visibility, the exact product-source target, and the exact
  closed asset name set;
- downloads and verifies the pinned candidate manifest before trusting its
  metadata rows for any other asset;
- streams each asset to a create-only temporary file;
- verifies exact size and SHA-256 before atomic rename;
- refuses links, reparse ancestors, pre-existing unexpected files, partial
  contracts, redirects to another host, and metadata disagreement;
- emits one machine-readable JSON result containing only non-secret release,
  path, asset, size, and digest facts;
- removes only task-created partial files after a failed download.

Both authority files are schema-validated. Updating a future release requires
a reviewed control-contract change after candidate construction; the
downloader never trusts live metadata to redefine the accepted set.

For operators who cannot provide `GITHUB_TOKEN`, the quickstart documents a
manual private-GitHub download path followed by the same local verification
gate. Authentication absence is a `HOLD`, not permission to use an unverified
cache.

### 3. Portable candidate construction

`scripts/build_preview.py` no longer contains `_S01_ROOT` or any developer
absolute path. `build_preview` accepts an explicit component root or exact
component paths from its caller. It validates each supplied binary against
`manifests/components.lock.json`, the closed component name set, expected file
name, version, digest, regular-file identity, and containment within the
caller-supplied root.

Package construction remains deterministic. Changing the input-path contract
must not relax component identity, hash, link, duplicate, or root-containment
checks.

### 4. Product skills

The bootstrap release packages the three skills required by the V1.2 operator
contract:

- `skills/thought-experiment/SKILL.md`;
- `skills/engineering-research/SKILL.md`;
- `skills/scope-to-deliverable-workflow/SKILL.md`.

Each skill declares its trigger, authority boundary, inputs, deterministic
evidence required before model judgment, outputs, stop conditions, private-data
rules, and handoff behavior. They are portable instructions and must contain no
local paths, receipts, transcripts, credentials, model secrets, or live state.

This slice does not invent the remaining four historical placeholder skills.
They remain out of scope unless a later product requirement names them.

### 5. Actionable privacy scanning

`scripts/scan_public_tree.py` keeps its existing fail-closed finding model but
adds deterministic operator output. On findings it prints one JSON object per
finding to standard output, sorted by relative path, rule, and detail, followed
by a non-secret summary on standard error. On a clean tree it prints a stable
zero-findings summary. Walk and read errors print a bounded error category and
relative path before returning nonzero.

Bytecode and cache artifacts remain prohibited in scanned release trees. The
scanner must name each offending relative path so an AI can remove only the
generated cache and rerun. Finding order cannot depend on filesystem traversal
order.

### 6. Clean-directory acceptance

Automated tests create a new temporary Windows directory with no repository
state and exercise the documented relative-path flow against controlled release
fixtures. The acceptance harness must prove:

- every referenced file exists in the built preview;
- no onboarding command depends on a developer checkout path;
- acquisition rejects wrong visibility, tag target, asset set, size, and hash;
- installer and verifier commands resolve from the documented relative layout;
- a clean installation verifies against the same archive and checksum;
- cache findings are named and ordered deterministically;
- the three required skills are present and pass the public-tree scanner;
- uninstall follows the documented fail-closed preservation behavior.

A separate native Windows acceptance record then starts from an empty operator
directory and follows only `README-FIRST.md`. Prior repository knowledge,
pre-existing AO components, cached release assets, and undocumented commands
invalidate that record.

## Data and control flow

1. The operator reads `README.md` in the private control repository.
2. The operator establishes `GITHUB_TOKEN` privately or selects the documented
   manual authenticated download path.
3. The acquisition script reads the tracked control contract, authenticates,
   verifies remote metadata, verifies the pinned candidate manifest, downloads
   its closed asset set, and verifies every byte before publication into
   `./downloads`.
4. After archive verification, the operator extracts a bootstrap copy, reads
   its `README-FIRST.md`, resolves an NTFS install root at runtime, and invokes
   the installer by a path relative to that verified extraction.
5. The verifier binds the installed tree back to the accepted archive and
   checksum sidecar.
6. The operator records the machine-readable acquisition and verification
   outputs, then stops. Office execution begins only after the separate
   lifecycle slice qualifies its command surface.

## Error handling and recovery

All scripts fail closed before mutating accepted state when authentication,
metadata, path, identity, hash, manifest, or platform checks disagree.
Task-created temporary files use unique names and are the only files eligible
for automatic cleanup. Existing files, ambiguous residues, rejected installs,
and prior installations are preserved and reported.

Documentation distinguishes recoverable operator errors from product defects:

- missing authentication, wrong directory, or occupied destination: correct the
  named input and rerun;
- digest, asset-set, visibility, or target disagreement: `HOLD` and preserve
  evidence;
- installer recovery marker or occupied office: follow the existing recovery
  guide; do not overwrite;
- undocumented state or path ambiguity: `HOLD` without cleanup.

## Testing strategy

Implementation follows behavior-focused TDD. Each defect begins with one test
that fails for the expected missing behavior, followed by the smallest change
that passes it.

Focused suites cover:

- README and runbook relative-link and forbidden-absolute-path checks;
- release-contract schema and downloader fail-closed behavior;
- portable preview construction from caller-supplied component roots;
- skill presence, required sections, and privacy scanning;
- deterministic scanner output and actionable cache findings;
- clean-directory install, verify, and uninstall flow.

Before integration, run the entire repository suite, parse every shipped JSON
schema and manifest, build the candidate twice and compare bytes, scan source
and generated artifacts, run `git diff --check`, and inspect the tracked diff
for private data and absolute paths. Native Windows qualification must use the
unchanged generated candidate bytes.

## Release and compatibility

This work produces a new private candidate rather than mutating
`developer-preview-v02`. The existing v02 archive and its qualification remain
immutable evidence. Candidate construction uses a product-source commit. After
the archive and external candidate manifest exist, a later control commit adds
their exact acquisition contract. The new documentation, scripts, skills,
candidate bytes, candidate manifest, and control contract are qualified as one
release chain without embedding a self-referential hash.

The first slice may be called bootstrap-ready only after clean-directory native
acceptance passes. It must not be called operationally ready. Operational
readiness requires the second slice: a user-facing lifecycle command for
status, claim, resume, execute, release, and recovery plus a standardized
endurance runner and real AO2/AO Mission workload evidence.

## Explicit non-goals

- macOS, Linux, WSL, UNC, removable-volume, or network-volume support;
- public release or repository visibility changes;
- automatic token creation, storage, or display;
- background services, schedulers, or unsolicited network updates;
- reimplementation of governed pool mutation in PowerShell;
- lifecycle command or real office execution in this first slice;
- modification of the already-published v02 release.
