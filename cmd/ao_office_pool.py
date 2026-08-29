import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from internal.execution import ExecutionError, execute
from internal.pool import MODES, OFFICE_IDS, Pool, PoolError


COMMANDS = frozenset({"status", "claim", "resume", "run", "release", "recover"})


class ArgumentError(RuntimeError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ArgumentError()


def _parser() -> Parser:
    parser = Parser(prog="ao-office-pool")
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")

    claim = commands.add_parser("claim")
    claim.add_argument("--owner", required=True)
    claim.add_argument("--task", required=True)
    claim.add_argument("--project", type=Path, required=True)
    claim.add_argument("--mode", choices=sorted(MODES), required=True)

    resume_parser = commands.add_parser("resume")
    resume_parser.add_argument("--receipt", type=Path, required=True)

    run = commands.add_parser("run")
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--envelope", type=Path, required=True)
    run.add_argument("--timeout", type=int, default=30)

    release = commands.add_parser("release")
    release.add_argument("--receipt", type=Path, required=True)

    recover = commands.add_parser("recover")
    recover.add_argument("--key", type=Path, required=True)
    recover.add_argument("--office", choices=OFFICE_IDS, required=True)
    recover.add_argument("--generation", type=int, required=True)
    return parser


def installed_pool(root: Path) -> Pool:
    try:
        root = Path(root).resolve(strict=False)
        metadata = json.loads((root / "pool.json").read_text(encoding="utf-8"))
        runtime_version = metadata["runtime_version"]
        if not isinstance(runtime_version, str):
            raise ValueError()
        return Pool(root, runtime_version=runtime_version)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise PoolError("invalid-installation") from error


def _authority_result(path: Path) -> dict:
    try:
        authority = json.loads(path.read_text(encoding="utf-8"))
        return {
            "authority_path": str(path),
            "office_id": authority["office_id"],
            "generation": authority["generation"],
        }
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise PoolError("recovery-required") from error


def dispatch(args) -> dict:
    pool = installed_pool(args.root)
    if args.command == "status":
        status = pool.public_status()
        return {"offices": status["offices"]}
    if args.command == "claim":
        return _authority_result(
            pool.claim(args.owner, args.task, args.project, args.mode)
        )
    if args.command == "resume":
        return _authority_result(pool.resume(args.receipt))
    if args.command == "run":
        result = execute(args.receipt, args.envelope, timeout_seconds=args.timeout)
        return {
            "execution_status": result.status,
            "record": str(result.record),
            "request_digest": result.request_digest,
        }
    if args.command == "release":
        pool.release(args.receipt)
        return {}
    pool.recover(args.key, args.office, args.generation)
    return {"office_id": args.office, "generation": args.generation}


def _command(arguments) -> str:
    return next((value for value in arguments if value in COMMANDS), "unknown")


def _write(stream, value) -> None:
    stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def main(arguments=None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    command = _command(arguments)
    try:
        args = _parser().parse_args(arguments)
        command = args.command
        result = dispatch(args)
        _write(
            sys.stdout,
            {"schema_version": 1, "command": command, "status": "ok", **result},
        )
        return 0
    except ArgumentError:
        code = "invalid-arguments"
        returncode = 2
    except (PoolError, ExecutionError) as error:
        code = error.code
        returncode = 2
    except Exception:
        code = "internal-error"
        returncode = 3
    _write(
        sys.stderr,
        {"schema_version": 1, "command": command, "status": "error", "code": code},
    )
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
