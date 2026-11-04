"""Legacy URL validation import. The wildcard-import scanner was replaced by urlscan_studio."""
from urlscan_studio.models import normalize_url, prepare_urls

__all__ = ["normalize_url", "prepare_urls"]
