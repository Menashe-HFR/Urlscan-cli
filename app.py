"""Vercel entry point: the public app has no filesystem persistence or background daemon."""
from urlscan_studio.cloud import app

__all__ = ["app"]
