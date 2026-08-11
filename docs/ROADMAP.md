# AO Office Pool Six-Month Roadmap

The roadmap targets one qualified Windows v1.2.0 release. Each month ends with
a usable checkpoint. Work does not advance when the month's exit gate fails.

## Month 1: Public foundation and five-office core

Build the public repository boundary, component lock format, portable manifest,
Windows path model, and the O1-O5 ownership lifecycle. Reuse the proven V1.1
claim, receipt, release, and update concepts after correcting the transferred
V1.2 blockers.

Exit gate:

- no secrets or local paths in tracked files;
- deterministic source-lock verification;
- atomic five-office claims under concurrent tests;
- full-house, stale-receipt, and contaminated-office tests pass;
- Windows path corpus runs in CI.

## Month 2: AO Mission front door

Connect office ownership to AO Mission. Store mission and continuation records
under the connected project's `.ao/` root. Add the standing task template and
resume flow without granting Mission execution authority.

Exit gate:

- one prompt creates one digest-bound mission record;
- a resumed conversation finds the same project and mission;
- another project or receipt cannot read protected state;
- bounded conversation can close without requiring a file deliverable;
- cancel and replacement complete an explicit release transition.

## Month 3: Blueprint and Atlas planning

Route underspecified work through Blueprint and oversized, mutation-class, or
long-running work through Atlas. Keep stack instances lightweight and point
them at shared tools and project-owned state.

Exit gate:

- Blueprint authorization is required before build-ready status;
- Atlas emits validated workgraphs and bounded context packs;
- blocked nodes cannot reach execution;
- project state survives office release and later resume;
- no AO source repository is copied into an office.

## Month 4: Governed Windows execution

Integrate Foundry, Forge, Covenant, and AO2. Stage a verified AO2 runtime and
copy identical accepted bytes into O1-O5. Bind execution paths to the connected
project and reject pool, sibling-project, alias, and traversal targets.

Exit gate:

- native Windows AO binaries report their accepted identities;
- Covenant decisions bind declared side effects and exact digests;
- five concurrent offices cannot cross-read or cross-release;
- activation requires all offices free;
- interrupted activation restores the previous runtime.

## Month 5: Readback, evaluation, and security hardening

Add Command readback and the bounded Arena, Crucible, Sentinel, and Promoter
gates needed for release qualification. Complete support-bundle allowlisting,
release leak scanning, emergency recovery, and adversarial Windows tests.

Exit gate:

- public status exposes only approved fields;
- support bundles contain no receipts, prompts, paths, or recovery data;
- adversarial path and state tests fail closed;
- evaluation and promotion records bind exact evidence digests;
- security review has no unresolved release blocker.

## Month 6: Qualification and public release

Freeze component identities, build on a clean Windows host, run the complete
five-office matrix twice, obtain independent review, and publish the exact
verified archive with checksums, SBOM, and provenance.

Exit gate:

- clean-room Windows install, update, rollback, and uninstall pass;
- O1-O5 read back independent equal runtime copies;
- all offices finish free with zero task-output residue;
- the public archive passes the leak scan and manifest verification;
- an independent evaluator reproduces the release result;
- the owner approves the license and public release.
