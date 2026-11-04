from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import sys
from pathlib import Path

from .models import prepare_urls
from .providers import DemoProvider, UrlscanProvider
from .reports import csv_report
from .service import Worker
from .store import Store


async def scan(args):
    values = [line.strip() for line in Path(args.file).read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not 1 <= len(values) <= 100:
        raise ValueError("Provide between 1 and 100 URLs per batch.")
    urls,duplicates = prepare_urls(values)
    key = os.getenv("URLSCAN_API_KEY","").strip()
    if args.provider == "urlscan" and not key:
        raise ValueError("Set URLSCAN_API_KEY for live scans.")
    provider = UrlscanProvider(key) if args.provider == "urlscan" else DemoProvider()
    store = Store(args.database)
    job_id,_ = store.create(urls,args.name,provider.name,args.visibility,duplicates,not args.no_cache)
    job = store.next_job(job_id=job_id)
    # CLI uses its own database by default; do not steal jobs from a running server.
    try:
        await Worker(store,provider,args.concurrency).process(job)
    finally:
        if hasattr(provider,"close"):
            await provider.close()
    result = store.job(job_id)
    destination = Path(args.output or f"output/investigation.{args.format}");destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(csv_report(result) if args.format=="csv" else json.dumps(result,indent=2),encoding="utf-8")
    print(f"{result['status']}: {len(urls)} URLs, {duplicates} duplicates removed. Report: {destination}")
    return 2 if result["status"] == "completed_with_errors" else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="URLScan Studio — durable URL investigations")
    sub = parser.add_subparsers(dest="command",required=True)
    serve = sub.add_parser("serve",help="Launch the local API and dashboard")
    serve.add_argument("--port",type=int,default=4180)
    scanner = sub.add_parser("scan",help="Process a file and export a JSON investigation")
    scanner.add_argument("file")
    scanner.add_argument("--provider",choices=["demo","urlscan"],default="demo")
    scanner.add_argument("--visibility",choices=["private","unlisted","public"],default="private")
    scanner.add_argument("--name",default="CLI investigation")
    scanner.add_argument("--concurrency",type=int,choices=range(1,9),default=3)
    scanner.add_argument("--database",default="cli-studio.db")
    scanner.add_argument("--format",choices=["json","csv"],default="json")
    scanner.add_argument("--output")
    scanner.add_argument("--no-cache",action="store_true")
    args = parser.parse_args(argv)
    if args.command == "serve":
        import uvicorn
        from .app import create_app
        uvicorn.run(create_app(),host="127.0.0.1",port=args.port)
        return 0
    try:
        return asyncio.run(scan(args))
    except (ValueError,OSError) as error:
        print(f"Error: {error}",file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
