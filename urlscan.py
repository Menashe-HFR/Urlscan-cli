"""Compatibility entry point. Prefer: python -m urlscan_studio.cli scan urls.txt."""
import sys
from urlscan_studio.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["scan", *sys.argv[1:]]))
