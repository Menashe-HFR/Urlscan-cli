from __future__ import annotations

import asyncio
import copy
import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx


class ProviderError(Exception):
    """An expected upstream error, safe to display without request headers or secrets."""


class DemoProvider:
    name = "demo"

    def __init__(self, delay=.45):
        self.delay = delay
        self.samples = json.loads((Path(__file__).parent / "web" / "samples.json").read_text(encoding="utf-8"))

    async def scan(self, url, visibility, resume_id=None, on_submitted=None):
        await asyncio.sleep(self.delay)
        host = urlsplit(url).hostname
        if host == "offline.test":
            raise ProviderError("Demo scenario: the upstream scan timed out. No URL was contacted.")
        result = self.samples["results"].get(host)
        if result is None:
            return {"source":"synthetic","verdict":"unknown","score":None,"http_status":None,
                    "title":"Custom URL in demo mode","final_url":url,"request_count":0,"domains":[],
                    "requests":[],"redirects":[],"findings":[{"severity":"info","title":"Not scanned",
                    "detail":"Demo mode never contacts this URL. Use the sample URLs or configure the live provider."}],
                    "scan_id":None,"report_url":None}
        return copy.deepcopy(result)


def normalize_result(data, url, scan_id):
    page, lists = data.get("page") or {}, data.get("lists") or {}
    verdicts = data.get("verdicts") or {}
    verdict = verdicts.get("overall") or verdicts.get("urlscan") or {}
    score = verdict.get("score")
    score = score if isinstance(score,(int,float)) and not isinstance(score,bool) else None
    malicious = verdict.get("malicious")
    label = "malicious" if malicious is True else "review" if score is not None and score > 0 else "no_flags" if malicious is False else "unknown"
    try:
        status = int(page["status"])
    except (KeyError,ValueError,TypeError):
        status = None
    if label == "no_flags" and (status is None or status >= 400):
        label = "unknown" if status is None else "review"
    domains = lists.get("domains") or []
    primary = page.get("domain") or urlsplit(url).hostname
    transactions = []
    for transaction in (data.get("data") or {}).get("requests",[])[:100]:
        request = (transaction.get("request") or {}).get("request") or {}
        response = (transaction.get("response") or {}).get("response") or {}
        transactions.append({"method":request.get("method","GET"),"url":request.get("url",""),
                             "status":response.get("status"),"type":transaction.get("type","Resource")})
    findings = []
    if label == "malicious":
        findings.append({"severity":"high","title":"Provider flagged this scan","detail":", ".join(verdict.get("categories") or []) or "The urlscan.io verdict reports malicious indicators."})
    elif label == "unknown":
        findings.append({"severity":"info","title":"Insufficient verdict data","detail":"Missing or incomplete evidence is not a clean result."})
    elif label == "no_flags":
        findings.append({"severity":"info","title":"No provider flags","detail":"No malicious flags in this observation; this is not a guarantee of safety."})
    else:
        findings.append({"severity":"medium","title":"Review recommended","detail":"The provider score or HTTP response warrants a closer look."})
    if url.startswith("http:"):
        findings.append({"severity":"medium","title":"HTTP starting URL","detail":"The submitted URL starts without transport encryption."})
    final_url = page.get("url") or url
    return {"source":"urlscan.io","verdict":label,"score":score,"http_status":status,
            "title":page.get("title") or primary,"final_url":final_url,"ip":page.get("ip"),
            "country":page.get("country"),"asn":page.get("asnname"),"tls_days":page.get("tlsValidDays"),
            "request_count":(data.get("stats") or {}).get("requests",len(transactions)),
            "domains":[{"domain":domain,"requests":sum(urlsplit(t["url"]).hostname==domain for t in transactions),"third_party":domain!=primary} for domain in domains[:100]],
            "requests":transactions,"redirects":[url,final_url] if final_url!=url else [],"findings":findings,
            "scan_id":scan_id,"report_url":f"https://urlscan.io/result/{scan_id}/"}


class UrlscanProvider:
    name = "urlscan"

    def __init__(self, key, *, client=None, sleep=asyncio.sleep, poll_interval=5, initial_wait=10, max_polls=30):
        self.client = client or httpx.AsyncClient(base_url="https://urlscan.io",timeout=20,
            follow_redirects=False,headers={"API-Key":key,"User-Agent":"URLScan-Studio/2.0"})
        self.sleep,self.poll_interval,self.initial_wait,self.max_polls = sleep,poll_interval,initial_wait,max_polls

    async def close(self):
        await self.client.aclose()

    async def request(self, method, path, **kwargs):
        # Follow only same-origin redirects: API keys must never leave the provider origin.
        for attempt in range(4):
            try:
                response = await self.client.request(method,path,**kwargs)
            except httpx.RequestError:
                if method != "GET" or attempt == 3:
                    raise ProviderError("Provider connection failed. Submission outcome may be unknown; no automatic resubmission was made.") from None
                await self.sleep(2**attempt)
                continue
            if response.is_redirect:
                destination = response.url.join(response.headers.get("location",""))
                if destination.scheme != "https" or destination.host != "urlscan.io" or destination.port not in (443,None):
                    raise ProviderError("Provider returned an unexpected redirect.")
                path = str(destination)
                continue
            if response.status_code == 429 or method == "GET" and response.status_code >= 500:
                if attempt == 3:
                    raise ProviderError(f"Provider HTTP {response.status_code}: retry budget exhausted.")
                raw = response.headers.get("Retry-After") or response.headers.get("X-Rate-Limit-Reset-After")
                try:
                    delay = max(1,float(raw)) if raw else 2**attempt
                except ValueError:
                    delay = 2**attempt
                if delay > 60:
                    raise ProviderError("Provider quota resets in more than a minute. Retry this batch later.")
                await self.sleep(delay)
                continue
            return response
        raise ProviderError("Provider redirect limit reached.")

    async def scan(self, url, visibility, resume_id=None, on_submitted=None):
        if resume_id:
            try:
                scan_id = str(uuid.UUID(resume_id))
            except ValueError:
                raise ProviderError("Invalid saved provider scan ID.") from None
        else:
            response = await self.request("POST","/api/v1/scan/",json={"url":url,"visibility":visibility,"tags":["urlscan-studio"]})
            if response.status_code != 200:
                raise ProviderError(f"Submission rejected (HTTP {response.status_code}). Check your API key, quota and visibility permissions.")
            try:
                scan_id = str(uuid.UUID(response.json()["uuid"]))
            except (ValueError,KeyError,TypeError):
                raise ProviderError("Provider returned an invalid submission response.") from None
            if on_submitted:
                on_submitted(scan_id)
            await self.sleep(self.initial_wait)
        for _ in range(self.max_polls):
            response = await self.request("GET",f"/api/v1/result/{scan_id}/")
            if response.status_code == 200:
                try:
                    data = response.json()
                    if not isinstance(data,dict):
                        raise ValueError()
                    return normalize_result(data,url,scan_id)
                except (ValueError,TypeError,AttributeError):
                    raise ProviderError("Provider returned malformed result data.") from None
            if response.status_code != 404:
                raise ProviderError(f"Result unavailable (HTTP {response.status_code}).")
            await self.sleep(self.poll_interval)
        raise ProviderError("Scan result deadline exceeded. The saved scan ID can be resumed by retrying the batch.")
