from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field
from typing import Literal


class BatchInput(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=100)
    name: str = Field(default="Untitled investigation", min_length=1, max_length=80)
    visibility: Literal["private", "unlisted", "public"] = "private"
    use_cache: bool = True


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 2048 or re.search(r"[\s\x00-\x1f\x7f]", value):
        raise ValueError("Use a URL of at most 2048 characters without spaces or control characters.")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        if parts.username is not None or parts.password is not None:
            raise ValueError("URLs containing credentials are not accepted.")
        host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.endswith((".local", ".localhost", ".internal")):
                raise ValueError("Use a public hostname.") from None
            if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in host.split(".")):
                raise ValueError("Invalid hostname.")
        else:
            if not address.is_global:
                raise ValueError("Private and reserved IP addresses are not accepted.")
            if address.version == 6:
                host = f"[{host}]"
        port = parts.port
        if port and not (parts.scheme == "https" and port == 443 or parts.scheme == "http" and port == 80):
            host += f":{port}"
        return urlunsplit((parts.scheme.lower(), host, parts.path or "/", parts.query, parts.fragment))
    except (UnicodeError, ValueError) as error:
        raise ValueError(str(error) or "Invalid URL.") from None


def prepare_urls(values: list[str]) -> tuple[list[str], int]:
    urls = []
    for index, value in enumerate(values, 1):
        try:
            normalized = normalize_url(value)
        except ValueError as error:
            raise ValueError(f"Line {index}: {error}") from None
        if normalized not in urls:
            urls.append(normalized)
    return urls, len(values) - len(urls)
