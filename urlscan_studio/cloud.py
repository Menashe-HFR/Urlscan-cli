"""Stateless Vercel adapter. No database writes or detached worker tasks."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .inspection import inspect_url, validate_target
from .providers import DemoProvider, ProviderError
from .previews import capture_preview

WEB = Path(__file__).parent / "web"
logger = logging.getLogger("urlscan.cloud")


class InspectionInput(BaseModel):
    urls: list[Annotated[str,Field(max_length=2048)]] = Field(min_length=1,max_length=6)
    name: str = Field(default="Website inspection",min_length=1,max_length=80)
    mode: Literal["live","sample"] = "live"


class PreviewInput(BaseModel):
    url: str = Field(min_length=1,max_length=2048)


def create_cloud_app():
    app = FastAPI(title="URLScan Studio · Public HTTP Inspection",version="2.1.0",
        description="Inspect public HTTP responses and explain observed headers. No browser execution or malware detection.")

    @app.middleware("http")
    async def boundaries(request: Request,call_next):
        if request.method not in {"GET","HEAD","OPTIONS"}:
            origin = request.headers.get("origin")
            if origin and (urlsplit(origin).netloc.lower()!=request.url.netloc.lower() or urlsplit(origin).scheme not in {"https","http"}):
                return Response("Cross-origin writes are disabled.",status_code=403)
            length = request.headers.get("content-length", "0")
            if not length.isdigit() or int(length)>32768:
                return Response("Request body is too large.",status_code=413)
        response = await call_next(request)
        response.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY",
            "Referrer-Policy":"strict-origin-when-cross-origin","Permissions-Policy":"camera=(), microphone=(), geolocation=()",
            "Cache-Control":"no-store" if request.url.path.startswith("/api/") else "no-cache"})
        if request.url.path=="/":
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://*.microlink.io https://microlink-cdn.s3.amazonaws.com https://urlscan.io; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response

    @app.get("/",response_class=HTMLResponse,include_in_schema=False)
    def index():
        return (WEB/"index.html").read_text(encoding="utf-8").replace('content="" name="api-base"','content="/api" name="api-base"')

    @app.get("/api/health")
    def health():
        return {"status":"ok","mode":"cloud","version":"2.1.0"}

    @app.get("/api/config")
    def config():
        return {"mode":"cloud","provider":"live-http","synthetic":False,"live_http":True,
            "max_urls":5,"history":"browser","concurrency":2,"cache_ttl":0,"screenshots":True,
            "scope":"HTTP status, redirects, security headers and bounded HTML metadata. No JavaScript execution or malware detection."}

    @app.post('/api/preview')
    async def preview(body: PreviewInput):
        try:
            validate_target(body.url)
        except ValueError as error:
            raise HTTPException(422,str(error)) from None
        return await capture_preview(body.url)

    @app.post("/api/inspect")
    async def inspect(batch: InspectionInput):
        if not batch.name.strip():
            raise HTTPException(422,"Give the inspection a name.")
        if batch.mode=="live" and len(batch.urls)>5:
            raise HTTPException(422,"A live inspection accepts at most five URLs.")
        try:
            urls = list(dict.fromkeys(validate_target(value) for value in batch.urls))
        except ValueError as error:
            raise HTTPException(422,str(error)) from None
        started = time.time()
        job_id = uuid.uuid4().hex
        job = {"id":job_id,"name":batch.name.strip(),"provider":"demo" if batch.mode=="sample" else "live-http",
            "visibility":"not-applicable","status":"running","created":started,"duplicates":len(batch.urls)-len(urls),
            "items":[],"events":[{"at":started,"seq":1,"message":f"Accepted {len(urls)} unique URLs · {'synthetic sample' if batch.mode=='sample' else 'live HTTP inspection'}."}]}
        semaphore = asyncio.Semaphore(2)
        demo = DemoProvider(delay=.02) if batch.mode=="sample" else None

        async def run(url):
            async with semaphore:
                try:
                    if demo:
                        result = await demo.scan(url,"private")
                        return {"url":url,"status":"completed","result":result,"error":None,"cached":False}
                    return await inspect_url(url)
                except ProviderError as error:
                    return {"url":url,"status":"failed","result":None,"error":str(error),"cached":False}
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Inspection failure, job %s",job_id)
                    return {"url":url,"status":"failed","result":None,"error":"The inspection could not finish. No safety verdict is available.","cached":False}

        tasks = [asyncio.create_task(run(url)) for url in urls]
        try:
            _,pending = await asyncio.wait(tasks,timeout=24)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending,return_exceptions=True)
            for index,(url,task) in enumerate(zip(urls,tasks)):
                item = task.result() if not task.cancelled() else {"url":url,"status":"failed","result":None,
                    "error":"The batch deadline was reached before this check finished.","cached":False}
                item["id"] = f"{job_id}-{index}"
                job["items"].append(item)
                job["events"].append({"at":time.time(),"seq":index+2,
                    "message":f"{urlsplit(url).hostname}: {item['status']}"})
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
        job["total"],job["done"] = len(urls),len(urls)
        job["status"] = "completed_with_errors" if any(item["status"]=="failed" for item in job["items"]) else "completed"
        job["duration_ms"] = round((time.time()-started)*1000)
        job["scope"] = "Synthetic fixtures; no external requests." if demo else config()["scope"]
        logger.info("Inspection %s: mode=%s urls=%s status=%s duration_ms=%s",job_id,batch.mode,len(urls),job["status"],job["duration_ms"])
        return job

    app.mount("/",StaticFiles(directory=WEB),name="web")
    return app


app = create_cloud_app()
