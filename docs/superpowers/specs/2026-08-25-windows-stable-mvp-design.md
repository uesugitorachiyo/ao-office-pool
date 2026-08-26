# AO Office Pool Windows Stable MVP Design

## Objective

Release a private Windows x86-64 AO Office Pool that binds one coherent AO
Stack, exposes one usable lifecycle command, and proves real installed work
through five isolated offices. The first stable gate favors a small operable
product over the broader high-assurance campaign.

## Scope

The release supports Windows x86-64, PowerShell 7, Python 3.12, and a fixed
local NTFS installation root. It has exactly five offices, O1 through O5. It
does not add a service, queue, scheduler, web interface, macOS support, Linux
support, or automatic network updater.

The existing pool lock, authority receipts, crash reconciliation, recovery
keys, and governed execution remain authoritative. This slice exposes those
capabilities; it does not replace them with a second implementation.

## Bootstrap boundary

Development and release assembly run from the isolated Git worktree, outside
AO Office Pool. An unqualified pool must not qualify itself.

After a candidate is checksum-bound, installed, and independently verified:

1. O1 runs the first claim, resume, governed run, release, and recovery
   dogfood workflow.
2. The installed bytes are verified unchanged.
3. The same bytes progress to O2 through O5, pool-full behavior, crash
   recovery, and the short soak campaign.

No dogfood result can replace checksum, installation, privacy, or archive
verification.

## Stack binding

`manifests/components.lock.json` is the single source of accepted component
identity. Every component row binds its repository, release version, source
commit, Windows asset name, license, and SHA-256 digest. Discovery uses
authoritative release metadata; acceptance uses downloaded bytes and their
computed hashes.

The candidate contains one immutable shared component tree. AO2 additionally
has five byte-identical office-local copies under O1 through O5. Packaging,
installation, and verification reject a missing, extra, renamed, linked, or
changed component.

Updating the lock and packaging constants is one atomic stack-rebinding
change. Partially mixing old and new stack identities is not accepted.

## Installed command

The installed entry point is `bin/ao-office-pool.ps1`. It locates its own
installation root and invokes the packaged Python CLI with Python 3.12. The
operator does not supply an installation root during normal lifecycle use.

The command has six subcommands:

- `status` returns sanitized O1-O5 status and generation values.
- `claim --owner ID --task TEXT --project PATH --mode MODE` claims the first
  free office and returns the private receipt path and assigned office.
- `resume --receipt PATH` validates and resumes the exact active authority.
- `run --receipt PATH --envelope PATH [--timeout SECONDS]` executes an
  already-issued governance envelope through the existing governed execution
  path. It does not create or bypass governance evidence.
- `release --receipt PATH` releases the exact authority after the existing
  dirty-state checks.
- `recover --office O1 --generation N --key PATH` performs the existing
  explicit recovery operation.

The CLI contains argument parsing and presentation only. Pool and execution
behavior remains in `internal.pool` and `internal.execution`.

## Output and failure contract

Each invocation writes exactly one JSON object to standard output on success.
The object includes `schema_version`, `command`, `status`, and only the fields
needed for the result. Runtime receipt paths are private operator output and
are never included in tracked evidence or release metadata.

Expected operational failures write one bounded JSON object to standard error
and exit nonzero. They expose the existing stable error code without a Python
traceback. Unexpected internal failures use `internal-error`, exit nonzero,
and omit private exception text. The command never retries a mutating
operation implicitly.

## Packaging and setup

The release archive includes the Python CLI, required `internal` modules, the
PowerShell launcher, and copy-and-paste instructions for both a human and an
AI operator. Installation validates Python 3.12 availability but does not
download or install Python.

The README path after `git clone` must identify source prerequisites, the
compiler qualification command, private-release acquisition, clean NTFS
installation, verification, and the first safe `status` command. The AI block
must prohibit publication and office work before the appropriate gates.

## Verification

Implementation follows behavior-focused red-green tests:

1. CLI parsing, exact JSON output, stable errors, and root discovery.
2. Real pool status, claim, resume, release, and recovery through the wrapper.
3. Governed `run` using the existing execution contract.
4. Stack-lock consistency across manifests, builder, installer, verifier, and
   immutable archive inventory.
5. Clean NTFS installation and independent verification.
6. O1 dogfood, followed by unchanged-byte O2-O5 operation, sixth-claim
   `pool-full`, and crash recovery.
7. A measured one-to-two-hour installed-product soak with bounded process,
   handle, memory, storage, and cleanup evidence.
8. Deterministic archive, schema parsing, public-tree privacy scan, and final
   private-release audit.

The final decision is exactly `RELEASE_READY`, `REPAIR`, or `HOLD`. Publishing
the private release remains a separately authorized final action.

## Deferred hardening

The first stable release does not require the eight-hour endurance campaign,
deep adversarial filesystem-race campaign, extensive update and rollback fault
injection, or non-Windows portability. Existing coverage is retained. These
items become the post-release hardening track and are added to the stable gate
only if real operating evidence justifies them.
