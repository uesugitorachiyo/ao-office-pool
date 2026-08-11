# AO Office Pool

AO Office Pool is a planned Windows-native coordination layer for five isolated
AO execution offices over one version-pinned AO stack. AO Mission accepts and
routes objectives. AO2 performs bounded execution. The pool binds each active
conversation to one office, one connected project, and one private receipt.

## Current status

This repository contains the approved architecture and development plan. It
does not contain a Production pool or qualified Windows release.

Development staging occurs on macOS. Windows qualification and Production
deployment will use a local NTFS volume and a configurable fixed installation
path. Local staging does not establish Windows readiness.

## Read first

1. [Architecture design](docs/superpowers/specs/2026-08-10-ao-office-pool-design.md)
2. [Six-month roadmap](docs/ROADMAP.md)
3. [Implementation plan](docs/superpowers/plans/2026-08-10-ao-office-pool-initial-development.md)

## Public repository boundary

Source, schemas, tests, sanitized fixtures, documentation, release manifests,
checksums, and SBOMs belong in Git. Runtime state, prompts, local project paths,
receipts, recovery material, operator secrets, and raw support bundles do not.

The ignored `.local/` directory holds machine-local handoffs and mission state.
The initial AO Mission handoff is located at:

`.local/handoffs/AO_MISSION_HANDOFF.md`

## Component sources

[AO Architecture](https://github.com/uesugitorachiyo/ao-architecture)
defines the stack contracts and compatibility view. Implementations come from
the linked component repositories. AO Office Pool will pin exact release or
commit identities in a verified lock manifest before packaging them.
