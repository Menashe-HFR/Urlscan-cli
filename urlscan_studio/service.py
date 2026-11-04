from __future__ import annotations

import asyncio
import json
import logging

from .providers import ProviderError

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, store, provider, concurrency=3, cache_ttl=3600):
        self.store,self.provider = store,provider
        self.concurrency = max(1,min(8,concurrency))
        self.cache_ttl = max(0,cache_ttl)

    async def run_item(self, job, item, semaphore):
        async with semaphore:
            if self.store.is_cancelled(job["id"]):
                return
            self.store.item_update(item["id"],status="running")
            self.store.event(job["id"],f"Inspecting {item['url']}")
            try:
                result = self.store.cached(item["url"],job["provider"],job["visibility"],self.cache_ttl) if job["use_cache"] else None
                cached = result is not None
                if result is None:
                    task = asyncio.create_task(asyncio.wait_for(self.provider.scan(item["url"],job["visibility"],item["scan_id"],
                        lambda value:self.store.item_update(item["id"],scan_id=value)),timeout=360))
                    try:
                        while not task.done():
                            await asyncio.wait({task},timeout=.1)
                            if self.store.is_cancelled(job["id"]):
                                return
                        result = task.result()
                    finally:
                        if not task.done():
                            task.cancel()
                            await asyncio.gather(task,return_exceptions=True)
                if not self.store.is_cancelled(job["id"]):
                    self.store.item_update(item["id"],status="completed",result=json.dumps(result),error=None,cached=int(cached))
                    self.store.event(job["id"],f"{'Cache hit' if cached else 'Completed'}: {item['url']} → {result['verdict']}")
            except (ProviderError,TimeoutError) as error:
                self.store.item_update(item["id"],status="failed",error=str(error) or "Scan deadline exceeded.")
                self.store.event(job["id"],f"Scan failed for {item['url']}: {str(error) or 'Deadline exceeded'}")
            except asyncio.CancelledError:
                # Preserve the provider UUID for restart recovery.
                raise
            except Exception:
                logger.exception("Unexpected worker failure for item %s",item["id"])
                self.store.item_update(item["id"],status="failed",error="Unexpected processing error. Check server logs.")

    async def process(self, job):
        self.store.event(job["id"],f"Worker started; concurrency limit {self.concurrency}.")
        semaphore = asyncio.Semaphore(self.concurrency)
        items = [item for item in self.store.items(job["id"]) if item["status"] == "queued"]
        await asyncio.gather(*(self.run_item(job,item,semaphore) for item in items))
        self.store.finish(job["id"])
        self.store.event(job["id"],"Batch processing finished.")

    async def run(self):
        self.store.recover(self.provider.name)
        while True:
            job = self.store.next_job(provider=self.provider.name)
            if job:
                await self.process(job)
            else:
                await asyncio.sleep(.1)
