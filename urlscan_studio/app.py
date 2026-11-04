from __future__ import annotations

import asyncio
import csv
import io
import os
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .models import BatchInput, prepare_urls
from .providers import DemoProvider, UrlscanProvider
from .reports import csv_report
from .service import Worker
from .store import Store

WEB = Path(__file__).parent / "web"


def create_app(database=None, provider=None, concurrency=None):
    store = Store(database or os.getenv("URLSCAN_DATABASE","studio.db"))
    provider_name = os.getenv("URLSCAN_PROVIDER","demo")
    if provider is None:
        if provider_name == "urlscan":
            key = os.getenv("URLSCAN_API_KEY","").strip()
            if not key:
                raise RuntimeError("Live provider requires URLSCAN_API_KEY. Use the demo provider without a key.")
            provider = UrlscanProvider(key)
        elif provider_name == "demo":
            provider = DemoProvider()
        else:
            raise RuntimeError("URLSCAN_PROVIDER must be demo or urlscan.")
    worker = Worker(store,provider,concurrency or int(os.getenv("URLSCAN_CONCURRENCY","3")),int(os.getenv("URLSCAN_CACHE_TTL","3600")))

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(worker.run())
        yield
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        if hasattr(provider,"close"):
            await provider.close()

    app = FastAPI(title="URLScan Studio",version="2.0.0",lifespan=lifespan,
        description="Durable batch URL investigations. Demo mode is synthetic; live mode requires your own urlscan.io key.")
    app.state.store,app.state.worker = store,worker
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=["localhost","127.0.0.1","[::1]","testserver"])

    @app.middleware("http")
    async def protect_origin(request: Request,call_next):
        origin = request.headers.get("origin")
        if request.method not in {"GET","HEAD","OPTIONS"} and origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
            return Response("Cross-origin writes are disabled.",status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
        return response

    @app.get("/",response_class=HTMLResponse,include_in_schema=False)
    def index():
        return (WEB/"index.html").read_text(encoding="utf-8").replace('content="" name="api-base"','content="/api" name="api-base"')

    @app.get("/api/health")
    def health():
        return {"status":"ok","provider":provider.name,"worker":"in-process","version":"2.0.0"}

    @app.get("/api/config")
    def config():
        return {"provider":provider.name,"concurrency":worker.concurrency,"max_urls":100,"cache_ttl":worker.cache_ttl,"synthetic":provider.name=="demo"}

    @app.get("/api/jobs")
    def history():
        return {"jobs":store.history()}

    @app.post("/api/jobs",status_code=202)
    def submit(batch: BatchInput,idempotency_key: str | None = Header(default=None,min_length=1,max_length=128)):
        try:
            if not batch.name.strip():
                raise ValueError("Give the investigation a name.")
            if idempotency_key is not None and not idempotency_key.strip():
                raise ValueError("Idempotency key must not be blank.")
            urls,duplicates = prepare_urls(batch.urls)
            job_id,created = store.create(urls,batch.name.strip(),provider.name,batch.visibility,duplicates,batch.use_cache,idempotency_key)
        except ValueError as error:
            raise HTTPException(409 if "Idempotency" in str(error) else 422,str(error)) from None
        except OverflowError as error:
            raise HTTPException(429,str(error)) from None
        return {"id":job_id,"created":created,"status_url":f"/api/jobs/{job_id}"}

    def get_job(job_id):
        job = store.job(job_id)
        if not job:
            raise HTTPException(404,"Investigation not found.")
        return job

    @app.get("/api/jobs/{job_id}")
    def detail(job_id: str):
        return get_job(job_id)

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel(job_id: str):
        get_job(job_id)
        store.cancel(job_id)
        store.event(job_id,"Cancellation requested; completed results are preserved.")
        return get_job(job_id)

    @app.post("/api/jobs/{job_id}/retry",status_code=202)
    def retry(job_id: str):
        if get_job(job_id)["provider"] != provider.name:
            raise HTTPException(409,"Select the provider that created this investigation before retrying it.")
        try:
            if not store.retry(job_id):
                raise HTTPException(409,"Only a finished batch with failed items can be retried.")
        except OverflowError as error:
            raise HTTPException(429,str(error)) from None
        store.event(job_id,"Retry requested for failed items only; saved provider scan IDs will be resumed.")
        return {"id":job_id}

    @app.get("/api/jobs/{job_id}/export")
    def export(job_id: str,format: str="csv"):
        job = get_job(job_id)
        if format == "json":
            import json
            return Response(json.dumps(job,indent=2),media_type="application/json",headers={"Content-Disposition":'attachment; filename="investigation.json"'})
        if format != "csv":
            raise HTTPException(422,"Choose csv or json.")
        return Response(csv_report(job),media_type="text/csv",headers={"Content-Disposition":'attachment; filename="investigation.csv"'})

    app.mount("/",StaticFiles(directory=WEB),name="web")
    return app
