# Repository instructions

Authority: platform-and-user > root-AGENTS > descendant-AGENTS
Descendants: narrow-only

## Scope and authority

- Platform policy and direct user instructions outrank this file.
- This file applies to the repository unless a descendant `AGENTS.md` narrows its subtree.
- A descendant file must declare `Authority: inherit-root` and `Descendants: narrow-only`.
- Descendant rules may add checks or reduce scope. They must not weaken root rules.
- Work within the requested task. Ask before expanding product scope or external effects.

## Privacy and release boundaries

- Keep prompts, transcripts, private model output, receipts, keys, tokens, and live state untracked.
- Keep developer and connected-project absolute paths out of tracked and public artifacts.
- Build public archives from `manifests/public-tree.json` with the release builder.
- Run the public-tree scanner before publication. Do not hand-curate around scanner findings.
- Do not publish, deploy, send, or mutate upstream systems without direct user authorization.

## Development

- Preserve unrelated user changes and inspect the working tree before edits.
- Use one behavior-focused RED to reproduce each defect before changing production code.
- Make the smallest GREEN change, then run focused regressions before the next defect.
- Keep tests tied to observable behavior and derive expected values outside production helpers.
- Treat journals, locks, receipts, manifests, and HMAC records as authority-bearing data.
- Fail closed on path ambiguity, identity drift, malformed authority, or incomplete recovery.

## Verification and claims

- Use fresh command output for test, build, privacy, and completion claims.
- Run focused tests during development and the full required suite before commit.
- Parse every shipped schema and scan generated public, protected, and support outputs.
- Run `git diff --check` and inspect the final diff for scope and private data.
- Mocked Windows branches on macOS prove portable decision logic only.
- Reserve native Windows compatibility claims for unchanged bytes tested on a Windows host.
