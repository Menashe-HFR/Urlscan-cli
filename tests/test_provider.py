import asyncio
import uuid

import httpx
import pytest

from urlscan_studio.providers import ProviderError, UrlscanProvider, normalize_result

SCAN_ID=str(uuid.UUID("12345678-1234-1234-1234-123456789abc"))


def run_with(handler,operation):
    async def run():
        sleeps=[]
        async def sleep(seconds):
            sleeps.append(seconds)
        client=httpx.AsyncClient(base_url="https://urlscan.io",transport=httpx.MockTransport(handler))
        provider=UrlscanProvider("not-a-real-key",client=client,sleep=sleep,initial_wait=10,max_polls=3)
        try:
            return await operation(provider,sleeps)
        finally:
            await provider.close()
    return asyncio.run(run())


def test_submit_poll_pending_and_save_id_before_polling():
    calls=[];saved=[]
    def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            assert b'"visibility":"private"' in request.content
            return httpx.Response(200,json={"uuid":SCAN_ID})
        assert saved == [SCAN_ID]
        return httpx.Response(404) if len(calls)==2 else httpx.Response(200,json={"page":{"status":200},"verdicts":{"overall":{"malicious":False,"score":-2}}})
    async def op(provider,sleeps):
        result=await provider.scan("https://example.com/","private",on_submitted=saved.append)
        assert result["verdict"] == "no_flags"
        assert sleeps == [10,5]
    run_with(handler,op)


def test_resume_does_not_submit_again():
    def handler(request):
        assert request.method == "GET"
        return httpx.Response(200,json={})
    async def op(provider,sleeps):
        assert (await provider.scan("https://example.com/","private",SCAN_ID))["verdict"] == "unknown"
        assert sleeps == []
    run_with(handler,op)


def test_rate_limit_wait_and_bounded_retries():
    count=0
    def handler(request):
        nonlocal count
        count+=1
        return httpx.Response(429,headers={"Retry-After":"3"})
    async def op(provider,sleeps):
        with pytest.raises(ProviderError,match="retry budget"):
            await provider.scan("https://example.com/","private")
        assert count==4 and sleeps==[3,3,3]
    run_with(handler,op)


def test_ambiguous_post_timeout_is_never_automatically_retried():
    calls=[]
    def handler(request):
        calls.append(request);raise httpx.ReadTimeout("secret request text",request=request)
    async def op(provider,sleeps):
        with pytest.raises(ProviderError,match="outcome may be unknown") as error:
            await provider.scan("https://example.com/","private")
        assert "secret" not in str(error.value) and len(calls)==1
    run_with(handler,op)


def test_off_origin_redirect_is_rejected():
    def handler(request):
        assert request.url.host == "urlscan.io"
        return httpx.Response(302,headers={"Location":"https://other.test/steal"})
    async def op(provider,sleeps):
        with pytest.raises(ProviderError,match="unexpected redirect"):
            await provider.scan("https://example.com/","private")
    run_with(handler,op)


def test_missing_fields_do_not_become_clean_or_crash():
    assert normalize_result({},"https://example.com/",SCAN_ID)["verdict"] == "unknown"
    assert normalize_result({"page":{"status":500},"verdicts":{"overall":{"malicious":False}}},"https://example.com/",SCAN_ID)["verdict"] == "review"
    assert normalize_result({"verdicts":{"overall":{"malicious":True,"score":94}}},"https://example.com/",SCAN_ID)["verdict"] == "malicious"
