from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .checks import DEFAULT_RPC_ENDPOINT, render_summary, run_preflight


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validator-preflight",
        description="Local preflight validator readiness checks with JSON stdout and operator summary on stderr.",
    )
    parser.add_argument("rpc_endpoint", nargs="?", default=DEFAULT_RPC_ENDPOINT, help=f"RPC endpoint to query (default: {DEFAULT_RPC_ENDPOINT})")
    parser.add_argument("--domain", help="Optional validator domain for DNS, TLS, and .well-known attestation checks.")
    parser.add_argument("--full", action="store_true", help="Run extended local checks such as /crawl, Docker, and disk space.")
    parser.add_argument("--upload-url", help="Optional HTTPS endpoint to receive the full JSON report via POST.")
    parser.add_argument("--json-only", action="store_true", help="Suppress the human-readable stderr summary.")
    return parser


async def _run(args: argparse.Namespace) -> int:
    report = await run_preflight(
        args.rpc_endpoint,
        domain=args.domain,
        full=args.full,
        upload_url=args.upload_url,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if not args.json_only:
        print(render_summary(report["checks"], color=sys.stderr.isatty()), file=sys.stderr)
    has_fail = any(check["status"] == "fail" for check in report["checks"])
    return 1 if has_fail else 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
