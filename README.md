# AO Office Pool

AO Office Pool is a planned Windows-native coordination layer for five isolated
AO execution offices over one version-pinned AO stack. AO Mission accepts and
routes objectives. AO2 performs receipt-bound execution. Each active project
conversation uses one office, one connected project, and one private receipt.

## Current status

This repository contains the approved architecture and a twelve-month
development path. It does not contain a Production pool or a qualified Windows
release.

Development staging occurs on macOS. Windows qualification and Production use
a fixed directory on a local NTFS volume. macOS evidence cannot establish
Windows readiness.

## Read first

1. [Architecture design](docs/superpowers/specs/2026-08-10-ao-office-pool-design.md)
2. [Months 1–6 roadmap](docs/ROADMAP.md)
3. [Months 7–12 roadmap](docs/ROADMAP_MONTHS_7_12.md)
4. [Implementation plan](docs/superpowers/plans/2026-08-10-ao-office-pool-initial-development.md)

## Public repository boundary

Git may contain source, schemas, tests, sanitized fixtures, documentation,
release manifests, checksums, SBOMs, and provenance. Git and release archives
must exclude prompts, transcripts, receipts, owner identities, recovery
material, absolute local paths, office state, private execution history, and
raw support data.

The ignored `.local/` directory holds machine-local handoffs, security drafts,
and mission state. AO Mission handoffs are stored at:

- `.local/handoffs/AO_MISSION_HANDOFF.md`
- `.local/handoffs/AO_MISSION_HANDOFF_MONTHS_7_12.md`

## Component sources

[AO Architecture](https://github.com/uesugitorachiyo/ao-architecture)
defines stack contracts and compatibility. Implementations come from the linked
component repositories. AO Office Pool will pin exact source, release, asset,
digest, license, and readiness identities before packaging or activation.

V1.1 and the transferred V1.2 candidate are requirement and regression sources.
They are not code-import authorities. V1.2 implementation must carry forward
validated behavior through new contracts and tests.
