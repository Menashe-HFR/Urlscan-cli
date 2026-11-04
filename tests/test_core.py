import asyncio
import json

import pytest

from urlscan_studio.models import normalize_url, prepare_urls
from urlscan_studio.providers import DemoProvider
from urlscan_studio.service import Worker
from urlscan_studio.store import Store


@pytest.mark.parametrize("value",["javascript:alert(1)","https://u:p@example.com","http://127.0.0.1","http://[::1]","http://10.0.0.1","localhost","http://service.local","https://bad host.com","https://-bad.test","https://example.com:99999"])
def test_invalid_urls(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_normalization_preserves_case_sensitive_paths_query_and_fragment():
    assert normalize_url(" HTTPS://EXAMPLE.COM:443/A?x=B#login ") == "https://example.com/A?x=B#login"
    assert prepare_urls(["atlas.test","https://ATLAS.test/"]) == (["https://atlas.test/"],1)
    assert normalize_url("https://münich.example") == "https://xn--mnich-kva.example/"


def add(store,urls=None,key=None,provider="demo",visibility="private"):
    return store.create(urls or ["https://atlas.test/"],"Test",provider,visibility,0,True,key)[0]


def test_idempotency_and_conflict_are_atomic(tmp_path):
    store=Store(str(tmp_path/"test.db"));first=add(store,key="request-1")
    assert add(store,key="request-1") == first
    with pytest.raises(ValueError):
        add(store,["https://different.test/"],key="request-1")
    assert len(store.history()) == 1


def test_queue_capacity(tmp_path):
    store=Store(str(tmp_path/"test.db"))
    for _ in range(20):
        add(store)
    with pytest.raises(OverflowError):
        add(store)


def test_recovery_preserves_provider_ids_and_other_providers(tmp_path):
    store=Store(str(tmp_path/"test.db"));job_id=add(store);other=add(store,provider="urlscan")
    store.next_job(provider="demo");store.next_job(provider="urlscan")
    item=store.items(job_id)[0];store.item_update(item["id"],status="running",scan_id="saved-id")
    store.recover("demo")
    assert store.job(job_id)["status"] == "queued"
    assert store.job(other)["status"] == "running"
    assert store.items(job_id)[0]["scan_id"] == "saved-id"
    assert store.items(job_id)[0]["status"] == "queued"


def test_cancellation_cannot_be_overwritten(tmp_path):
    store=Store(str(tmp_path/"test.db"));job_id=add(store);item=store.items(job_id)[0]
    store.cancel(job_id);store.item_update(item["id"],status="completed",result='{}');store.finish(job_id)
    assert store.job(job_id)["status"] == "cancelled"
    assert store.items(job_id)[0]["status"] == "cancelled"


def test_worker_isolates_failures_and_cache_is_scoped(tmp_path):
    store=Store(str(tmp_path/"test.db"));job_id=add(store,["https://atlas.test/","https://offline.test/"])
    worker=Worker(store,DemoProvider(delay=0));asyncio.run(worker.process(store.next_job()))
    job=store.job(job_id)
    assert job["status"] == "completed_with_errors"
    assert [item["status"] for item in job["items"]] == ["completed","failed"]
    assert store.cached("https://atlas.test/","demo","private",3600)["source"] == "synthetic"
    assert store.cached("https://atlas.test/","urlscan","private",3600) is None
    assert store.cached("https://atlas.test/","demo","public",3600) is None
    assert store.cached("https://atlas.test/","demo","private",0) is None
    again=add(store);asyncio.run(worker.process(store.next_job()))
    assert store.job(again)["items"][0]["cached"] == 1
    assert store.retry(job_id) is True
    assert [item["status"] for item in store.items(job_id)] == ["completed","queued"]


def test_worker_bounds_concurrency_and_cancels_inflight(tmp_path):
    class Slow(DemoProvider):
        running=0;peak=0
        async def scan(self,*args,**kwargs):
            self.running+=1;self.peak=max(self.peak,self.running)
            try:
                await asyncio.sleep(10)
            finally:
                self.running-=1
    async def run():
        store=Store(str(tmp_path/"test.db"));job_id=add(store,[f"https://site{i}.test/" for i in range(8)])
        provider=Slow();task=asyncio.create_task(Worker(store,provider,2).process(store.next_job()))
        await asyncio.sleep(.03);store.cancel(job_id)
        await asyncio.wait_for(task,1)
        assert provider.peak == 2 and provider.running == 0
        assert all(item["status"] == "cancelled" for item in store.items(job_id))
    asyncio.run(run())


def test_custom_demo_url_is_unknown_not_fabricated_clean():
    result=asyncio.run(DemoProvider(0).scan("https://example.com/","private"))
    assert result["verdict"] == "unknown" and result["score"] is None


def test_csv_cells_cannot_execute_spreadsheet_formulas():
    from urlscan_studio.reports import csv_report
    job={"provider":"demo","items":[{"url":"https://atlas.test/","status":"completed","result":{"country":"=1+1"},"cached":0,"error":"@SUM(1,2)"}]}
    report=csv_report(job)
    assert "'=1+1" in report and "'@SUM" in report
