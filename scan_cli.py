"""Async CLI that uses the ghosttrace registry and AsyncScannerManager.

This runner performs async scans using the new plugin registry. It is
backwards-compatible for quick local testing and supports filtering by
checker id(s).

Usage: python scan_cli.py email@example.com [--layer surface] [--id example_surface]
"""
import argparse
import asyncio
from typing import Set

from ghosttrace.core.registry import registry
from ghosttrace.core.manager import AsyncScannerManager


def parse_args():
    p = argparse.ArgumentParser(description="GhostTrace async CLI scanner")
    p.add_argument("email", help="Email address to scan")
    p.add_argument("--layer", default="surface", help="Checker layer to run (default: surface)")
    p.add_argument("--id", default="", help="Comma-separated checker IDs to run only")
    return p.parse_args()


def format_line(result: dict) -> str:
    status = result.get("status", "unknown").upper()
    name = result.get("name", "?")
    details = result.get("details", "")
    return f"{status:12}  {name:30}  {details}"


async def run_scan(email: str, layer: str, only_ids: Set[str]):
    registry.discover_plugins("ghosttrace.checkers")
    manager = AsyncScannerManager()
    results = []

    async for event in manager.scan_email(email, layer=layer, config={}):
        if event.get("type") == "result":
            if only_ids and event.get("id") not in only_ids:
                continue
            results.append(event)
            print(format_line(event))
        elif event.get("type") == "progress":
            cur = event.get("current")
            tot = event.get("total")
            checking = event.get("checking")
            print(f"Progress: {cur}/{tot} — {checking}")

    return results


def main():
    args = parse_args()
    email = args.email.strip().lower()
    only_ids = {x.strip() for x in args.id.split(",") if x.strip()}

    print(f"Scanning: {email}  (layer={args.layer})")
    asyncio.run(run_scan(email, args.layer, only_ids))


if __name__ == "__main__":
    main()
