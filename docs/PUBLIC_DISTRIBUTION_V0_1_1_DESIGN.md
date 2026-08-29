# AO Office Pool v0.1.1 Public Distribution Design

Date: 2026-08-27
Status: approved for implementation planning

## Purpose and scope

AO Office Pool v0.1.1 will be the first supported public release of this
Windows-only project. A new user must be able to clone the repository and use
one copy-and-paste PowerShell command to download, verify, install, initialize,
and smoke-test the product without a GitHub credential.

AO Office Pool remains an independent project. It integrates pinned AO Stack
components but is not currently an official member of the AO Stack family.
macOS, Linux, CI/CD expansion, and a broader release-governance redesign are
outside this change.

The existing v0.1.0 release remains a historical artifact originally issued as
a private preview. Once repository visibility changes, its release page must
label it unsupported and superseded. Its archive does not contain a project
license or notice, so it must not be presented as the first supported public
distribution.

## User experience

The first README screen will identify the supported platform and provide one
ordinary user path:

```powershell
git clone https://github.com/uesugitorachiyo/ao-office-pool.git
Set-Location ao-office-pool
pwsh -File .\scripts\Install-And-Verify.ps1
```

The command will finish with `READY FOR USE` only after the installed product
reports exactly O1 through O5, all initially free, and completes a disposable
O1 claim/resume/release lifecycle with all five offices free afterward.

The README will also contain one self-contained AI prompt directing a Windows
Codex task to run the same script unchanged, stop at the first closed gate,
and return a concise evidence summary. It will not duplicate the implementation
commands embedded in the script.

Contributor source qualification, including Visual Studio Build Tools and the
full native test suite, will remain documented below the user path. Maintainer
publication instructions will move to a dedicated document and will not be
part of the ordinary install flow.

## Licensing and project identity

The repository and release archive will include the canonical Apache License
2.0 text in `LICENSE`.

`NOTICE` will:

- identify AO Office Pool and its copyright holder;
- state that it is an independent project, not currently an AO Stack family
  component;
- enumerate the pinned AO components distributed in the release and their
  Apache-2.0 license identity; and
- point to `manifests/components.lock.json` for exact versions, repositories,
  commits, asset names, and checksums.

The archive builder and verifier will require both `LICENSE` and `NOTICE`.
Missing or altered licensing files will fail the build and installation
contracts rather than being treated as optional documentation.

## Public acquisition and verification

`scripts/Install-And-Verify.ps1` will be the public entry point. It will use
only unauthenticated HTTPS requests to the public GitHub release for the exact
`v0.1.1` tag. It will not accept a mutable `latest` target and will not inspect,
request, print, or persist `GITHUB_TOKEN`.

The script will:

1. Require Windows x86-64 and PowerShell 7 or newer.
2. Require Python 3.12 and the Microsoft Visual C++ v14 Redistributable x64.
3. Require a fixed local NTFS installation target with adequate path budget.
4. Fetch the exact v0.1.1 release metadata and require the closed expected
   asset set.
5. Download the archive and checksum sidecar to a new local staging directory.
6. Validate the sidecar format, filename binding, pinned SHA-256, archive hash,
   release tag, and source identity before extraction.
7. Install through the existing installer into a new local path.
8. Run the existing package verifier against the independently retained
   archive and sidecar.
9. Verify O1-O5 are free, exercise O1 claim/resume/release in a disposable Git
   repository, and verify O1-O5 are free again.
10. Print the installed launcher path, compact usage examples, and
    `READY FOR USE`.

The public script will use a fixed default install location suitable for an
ordinary user but permit an explicit safe local NTFS override. It will never
overwrite an existing installation implicitly. Network, metadata, digest,
path, prerequisite, installation, or lifecycle ambiguity will return `HOLD`
with one actionable reason.

The existing authenticated and offline acquisition implementation may remain
for compatibility and maintainer use, but it will not appear in the primary
README or AI installation path.

## Release construction

The v0.1.1 archive will be built from a clean, committed source revision using
the manifest-driven release builder. The public-tree manifest will be updated
only for the new intentional public files: `LICENSE`, `NOTICE`, the public
installer, its tests, and the maintainer documentation selected for release.

The release contract will bind:

- repository identity;
- exact `v0.1.1` tag and source commit;
- Windows x86-64 architecture;
- exact archive and sidecar filenames;
- archive size and SHA-256;
- component-lock digest and all component identities; and
- public release visibility.

The archive will remain deterministic. The release will not reuse or replace
the v0.1.0 archive bytes, checksum, tag, or source identity.

## Pre-public exposure audit

Repository visibility will change only after all of these gates pass:

1. The current tracked tree passes the public-tree scanner.
2. Every Git object reachable from all refs is scanned for credentials,
   private paths, prompts, transcripts, receipts, recovery keys, and live
   state, including content deleted from the current tree.
3. Existing releases and every downloadable asset are inventoried and scanned.
4. Repository-visible issues, pull requests, discussions, wiki content,
   Actions logs and artifacts, packages, Pages, environments, deploy keys,
   webhooks, and repository settings are reviewed for private data and unsafe
   exposure.
5. The v0.1.1 archive is extracted and scanned independently; every schema and
   manifest parses; every native binary matches the component lock.
6. Apache-2.0 redistribution requirements for all bundled AO components are
   represented by the archive's `LICENSE`, `NOTICE`, and component lock.

Any confirmed secret or private artifact stops the visibility change. History
rewriting or remote deletion requires a separately reviewed target list and
explicit approval because those operations are destructive.

## Verification strategy

Implementation will use behavior-focused tests for:

- public installation without `GITHUB_TOKEN`;
- rejection of mutable tags, unexpected asset sets, redirects to unapproved
  hosts, malformed sidecars, digest drift, and partial downloads;
- required `LICENSE` and `NOTICE` membership and deterministic archive bytes;
- safe NTFS/path handling and refusal to overwrite an existing installation;
- initial and final O1-O5 all-free status;
- the disposable O1 claim/resume/release lifecycle;
- README and AI-prompt parity with the actual script; and
- retention of the contributor-only Visual Studio distinction.

Before publication, the unchanged release candidate must pass focused tests,
the full required Windows suite, schema parsing, public-tree scanning,
deterministic build comparison, clean-install verification, and the exposure
audit. After visibility changes, a fresh unauthenticated Windows clone will run
the README command verbatim. The result is `READY` only if that public clone
completes installation and the real lifecycle smoke test.

## Publication sequence and rollback

The sequence is deliberately one-way at the user boundary:

1. Implement and qualify v0.1.1 on a feature branch.
2. Merge and push the qualified source to the default branch.
3. Create the checksum-bound v0.1.1 release from the pinned tag.
4. Complete the repository-history and GitHub-surface exposure audit.
5. Change repository visibility to public.
6. Enable GitHub secret scanning and push protection when available.
7. Run the clean unauthenticated Windows installation and smoke test.

If the post-visibility clean installation fails, mark v0.1.1 unsupported or
remove it from the recommended path while preserving evidence, fix forward on
a new patch release, and avoid silently replacing published bytes. If private
data is discovered after exposure, make the repository private immediately,
revoke affected credentials, preserve an incident inventory, and repair or
rewrite only the explicitly verified affected surfaces.

## Completion criteria

The work is complete when:

- the repository and v0.1.1 archive carry Apache-2.0 licensing and notices;
- README offers one correct unauthenticated copy-and-paste Windows install path
  and one matching AI prompt;
- the v0.1.1 public release is checksum- and source-bound;
- the complete local and GitHub exposure audit has no unresolved findings;
- repository visibility is public with appropriate secret protections; and
- a clean Windows user without credentials reaches `READY FOR USE` and can use
  the installed O1-O5 lifecycle command.
