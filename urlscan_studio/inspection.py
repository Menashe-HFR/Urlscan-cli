"""Bounded HTTP evidence collection. This does not execute pages or detect malware."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend

from .models import normalize_url

MAX_BODY = 512 * 1024
MAX_REDIRECTS = 5


class UnsafeTarget(ValueError):
    pass


def validate_target(value: str) -> str:
    normalized = normalize_url(value)
    parts = urlsplit(normalized)
    if parts.port not in (None, 80, 443):
        raise UnsafeTarget("Only public web URLs on ports 80 and 443 are accepted.")
    host = parts.hostname or ""
    # Reject noncanonical numeric hosts that some network stacks reinterpret as loopback.
    if host.replace(".", "").isdigit() and len(host.split(".")) != 4:
        raise UnsafeTarget("Use a public hostname or a canonical public IP address.")
    return normalized


def is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            parsed = parsed.ipv4_mapped
        return parsed.is_global and not parsed.is_multicast
    except ValueError:
        return False


async def resolve_public(host: str, port: int) -> list[str]:
    records = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM), timeout=3)
    return list(dict.fromkeys(record[4][0] for record in records))


class PublicNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve once, validate every answer, connect to literal IP; TLS keeps original SNI."""

    def __init__(self, resolver=resolve_public, backend=None):
        self.resolver = resolver
        self.backend = backend or AutoBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if isinstance(host, bytes):
            host = host.decode("ascii")
        try:
            literal = str(ipaddress.ip_address(host))
        except ValueError:
            addresses = await self.resolver(host, port)
        else:
            addresses = [literal]
        if not addresses or any(not is_public(address) for address in addresses):
            raise UnsafeTarget("The target does not resolve exclusively to public addresses.")
        last_error = None
        for address in addresses[:4]:
            try:
                return await self.backend.connect_tcp(address, port, timeout=timeout,
                    local_address=local_address, socket_options=socket_options)
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as error:
                last_error = error
        if last_error:
            raise last_error
        raise UnsafeTarget("No public connection was available.")

    async def connect_unix_socket(self, *args, **kwargs):
        raise UnsafeTarget("Unix sockets are not supported.")

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


class ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        async for chunk in self.stream:
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class PublicTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.pool = httpcore.AsyncConnectionPool(ssl_context=ssl.create_default_context(),
            network_backend=PublicNetworkBackend(), max_connections=2, max_keepalive_connections=0,
            retries=0, http1=True, http2=False)

    async def handle_async_request(self, request):
        core_request = httpcore.Request(method=request.method,
            url=httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host,
                port=request.url.port, target=request.url.raw_path),
            headers=request.headers.raw, content=request.stream, extensions=request.extensions)
        response = await self.pool.handle_async_request(core_request)
        return httpx.Response(response.status, headers=response.headers,
            stream=ResponseStream(response.stream), extensions=response.extensions)

    async def aclose(self):
        await self.pool.aclose()


class PageMetadata(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.title, self.description = base, "", ""
        self.in_title = False
        self.references = []
        self.links = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "meta" and (attrs.get("name") or "").lower() == "description":
            self.description = (attrs.get("content") or "")[:600]
        if tag == "a" and attrs.get("href"):
            self.links += 1
        reference = attrs.get("src") if tag in {"script", "img", "iframe", "source"} else attrs.get("href") if tag == "link" else None
        if reference and len(self.references) < 150:
            try:
                absolute = urljoin(self.base, reference)
                parsed = urlsplit(absolute)
                if parsed.scheme in {"http", "https"} and parsed.hostname:
                    self.references.append({"host":parsed.hostname,"url":absolute[:2048],"type":tag})
            except ValueError:
                pass

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title and len(self.title) < 300:
            self.title += data[:300-len(self.title)]


def analyse_response(requested_url, final_url, status, headers, body, duration_ms, chain, truncated):
    headers = {key.lower():value for key,value in headers.items()}
    parser = PageMetadata(final_url)
    html = "html" in headers.get("content-type", "").lower()
    if html:
        parser.feed(body)
    https = urlsplit(final_url).scheme == "https"
    csp = headers.get("content-security-policy", "")
    hsts = headers.get("strict-transport-security", "")
    import re
    hsts_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)",hsts,re.I)
    frame = headers.get("x-frame-options", "").lower().strip()
    ancestors = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)",csp,re.I)
    if ancestors:
        sources = ancestors.group(1).split()
        def restricted_source(value):
            if value in {"'none'","'self'"}:
                return True
            try:
                parsed = urlsplit(value)
                return parsed.scheme in {"https","http"} and bool(parsed.hostname) and parsed.hostname!="*"
            except ValueError:
                return False
        framing_protected = bool(sources) and all(restricted_source(source) for source in sources)
    else:
        framing_protected = frame in {"deny","sameorigin"}
    checks = [
        ("https","HTTPS transport",https,"high","Use HTTPS for the final destination and redirect HTTP links to it."),
        ("status","Successful HTTP response",200 <= status < 400,"medium","Review the HTTP error or access restriction before relying on page-level evidence."),
        ("csp","Content Security Policy",bool(csp.strip()),"medium","Consider a Content-Security-Policy header tailored to the scripts and resources the application needs."),
        ("hsts","Strict Transport Security",https and bool(hsts_age and int(hsts_age.group(1)) > 0),"medium","On HTTPS responses, consider Strict-Transport-Security with a positive max-age after confirming HTTPS readiness."),
        ("framing","Framing protection",framing_protected,"medium","Consider a restrictive CSP frame-ancestors directive or X-Frame-Options to control who can embed this page."),
        ("nosniff","MIME sniffing protection",headers.get("x-content-type-options","").lower().strip()=="nosniff","medium","Consider X-Content-Type-Options: nosniff together with accurate Content-Type headers."),
        ("referrer","Explicit referrer policy",headers.get("referrer-policy","").lower().strip() in {"no-referrer","same-origin","strict-origin","strict-origin-when-cross-origin","origin","origin-when-cross-origin"},"info","Consider an explicit Referrer-Policy appropriate for the application."),
        ("permissions","Permissions policy",bool(headers.get("permissions-policy","").strip()),"info","Consider a Permissions-Policy that disables browser features this page does not need."),
    ]
    findings = [{"severity":severity,"title":label+" not observed" if key not in {"https","status"} else label+" needs review",
        "detail":recommendation} for key,label,passed,severity,recommendation in checks if not passed]
    if not html:
        findings.append({"severity":"info","title":"Non-HTML response","detail":"Header and transport checks are available; HTML metadata and resource references were not inspected."})
    if truncated:
        findings.append({"severity":"info","title":"Page body was truncated","detail":"Only the first 512 KiB were read. Resource references and metadata may be incomplete."})
    if duration_ms > 2000:
        findings.append({"severity":"info","title":"Slow response observed","detail":f"This request took {duration_ms/1000:.1f}s. Measure again from your users' regions before diagnosing a performance issue."})
    if not findings:
        findings.append({"severity":"info","title":"Baseline checks passed","detail":"The observed HTTP response passed this limited checklist. No malware, content or full browser audit was performed."})
    passed = sum(item[2] for item in checks)
    priority = sum(f["severity"] in {"high","medium"} for f in findings)
    host = urlsplit(final_url).hostname
    navigation_hosts = Counter(urlsplit(step["url"]).hostname for step in chain)
    referenced_hosts = Counter(reference["host"] for reference in parser.references)
    domain_rows = [{"domain":domain,"requests":count,"third_party":domain!=host,"observed":True}
        for domain,count in navigation_hosts.items()]
    domain_rows += [{"domain":domain,"requests":None,"references":count,"third_party":domain!=host,"observed":False}
        for domain,count in referenced_hosts.items() if domain not in navigation_hosts]
    selected_headers = {name:headers[name][:4000] for name in ("content-type","content-security-policy",
        "strict-transport-security","x-frame-options","x-content-type-options","referrer-policy",
        "permissions-policy","cache-control") if name in headers}
    return {"source":"live-http","verdict":"review" if priority else "no_flags","score":None,
        "title":parser.title.strip() or host,"description":parser.description,"http_status":status,
        "final_url":final_url,"ip":None,"country":None,"asn":None,"tls_days":None,
        "duration_ms":round(duration_ms),"posture":{"passed":passed,"total":len(checks)},
        "summary":f"{passed} of {len(checks)} baseline HTTP checks passed. "+(f"{priority} findings deserve review." if priority else "No priority findings in this limited inspection."),
        "checks":[{"id":key,"label":label,"passed":bool(ok),"severity":severity,"recommendation":advice}
            for key,label,ok,severity,advice in checks],"headers":selected_headers,
        "request_count":len(chain),"domains":domain_rows,"resource_references":parser.references,
        "findings":findings,"requests":[{"method":"GET","url":step["url"],"status":step["status"],"type":"HTTP navigation"} for step in chain],
        "redirects":[step["url"] for step in chain] if len(chain)>1 else [],"scan_id":None,
        "report_url":None,"body_truncated":truncated,"scope":"HTTP headers, redirects and a bounded HTML read; no JavaScript execution or malware detection."}


async def _inspect(url, client):
    started = time.monotonic()
    current, visited, chain = validate_target(url), set(), []
    for _ in range(MAX_REDIRECTS+1):
        current = validate_target(current)
        if current in visited:
            raise ValueError("The public URL entered a redirect loop.")
        visited.add(current)
        async with client.stream("GET",current,follow_redirects=False,
                headers={"User-Agent":"URLScan-Studio/2.1 (+https://github.com/Menashe-HFR/Urlscan-cli)","Accept":"text/html,application/xhtml+xml,*/*;q=0.5","Accept-Encoding":"identity"}) as response:
            chain.append({"url":current,"status":response.status_code})
            if response.status_code in {301,302,303,307,308}:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("The server redirected without a destination.")
                current = validate_target(urljoin(current,location))
                continue
            encoding = response.headers.get("content-encoding", "identity").lower()
            if encoding not in {"identity", ""}:
                raise ValueError("The server forced a compressed response. This bounded inspection cannot safely read it.")
            body = bytearray(); truncated = False
            async for chunk in response.aiter_bytes(chunk_size=16384):
                remaining = MAX_BODY-len(body)
                body.extend(chunk[:remaining])
                if len(chunk)>remaining:
                    truncated = True
                    break
            text = bytes(body).decode("utf-8",errors="replace")
            result = analyse_response(url,current,response.status_code,response.headers,text,
                (time.monotonic()-started)*1000,chain,truncated)
            return {"url":url,"status":"completed","result":result,"error":None,"cached":False}
    raise ValueError("The public URL exceeded the five-redirect limit.")


async def inspect_url(url, *, client=None):
    try:
        async with asyncio.timeout(20):
            if client is not None:
                return await _inspect(url,client)
            async with httpx.AsyncClient(transport=PublicTransport(),timeout=httpx.Timeout(7,connect=4),
                    trust_env=False,follow_redirects=False) as connection:
                return await _inspect(url,connection)
    except (UnsafeTarget,ValueError) as error:
        message = str(error)
        if "public" not in message.lower() and "redirect" not in message.lower() and "compressed" not in message.lower():
            message = "Only valid public HTTP(S) URLs can be inspected. " + message
    except (TimeoutError,httpx.TimeoutException,httpcore.TimeoutException):
        message = "The inspection timed out. No safety verdict is available."
    except (httpx.HTTPError,httpcore.NetworkError,httpcore.ProtocolError,ssl.SSLError,OSError):
        message = "A public connection or TLS validation failed. No safety verdict is available."
    return {"url":url,"status":"failed","result":None,"error":message,"cached":False}
