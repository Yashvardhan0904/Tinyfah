from __future__ import annotations

import argparse
import asyncio
import json

from app.agent.llm import LLMConfigurationError, describe_chain
from app.agent.runner import resume_explore, run_explore
from app.core.audit import new_run_id
from app.models.db import create_run
from app.services.recon import perform_recon


def _providers() -> int:
    try:
        for label in describe_chain():
            print(label)
    except LLMConfigurationError as exc:
        print(f"error: {exc}")
        return 1
    return 0


def _recon(target: str) -> int:
    try:
        result = asyncio.run(perform_recon(target))
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0


def _explore(target: str) -> int:
    run_id = new_run_id()
    try:
        create_run(run_id, target, mode="explore")
        result = asyncio.run(run_explore(run_id, target))
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") in {"completed", "awaiting_approval"} else 1


def _sqli(target: str) -> int:
    run_id = new_run_id()
    try:
        create_run(run_id, target, mode="sqli")
        result = asyncio.run(run_explore(run_id, target, mode="sqli"))
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") in {"completed", "awaiting_approval"} else 1


def _approve(run_id: str, approved: bool) -> int:
    try:
        result = asyncio.run(resume_explore(run_id, approved))
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") in {"completed", "awaiting_approval"} else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tinyfah-exploit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("providers", help="Show the configured LLM fallback chain")

    recon_parser = subparsers.add_parser("recon", help="Run a read-only browser recon")
    recon_parser.add_argument("target", help="Allowlisted https target URL")

    explore_parser = subparsers.add_parser(
        "explore", help="Run the playbook graph against an owned target"
    )
    explore_parser.add_argument("target", help="Allowlisted https target URL")

    sqli_parser = subparsers.add_parser(
        "sqli", help="Run SQL injection login checks against an owned target"
    )
    sqli_parser.add_argument("target", help="Allowlisted https target URL")

    approve_parser = subparsers.add_parser("approve", help="Approve or deny a pending action")
    approve_parser.add_argument("run_id", help="Run id awaiting approval")
    approve_parser.add_argument("--deny", action="store_true", help="Deny instead of approving")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "providers":
        return _providers()
    if args.command == "recon":
        return _recon(args.target)
    if args.command == "explore":
        return _explore(args.target)
    if args.command == "sqli":
        return _sqli(args.target)
    if args.command == "approve":
        return _approve(args.run_id, not args.deny)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
