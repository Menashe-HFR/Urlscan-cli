import asyncio
import importlib

import httpx


def previews():return importlib.import_module('urlscan_studio.previews')

async def public_resolver(host,port):return ['93.184.216.34']


def test_provider_screenshot_is_source_labeled_and_not_falsely_dated():
    def handler(request):
        assert request.url.host=='api.microlink.io'
        return httpx.Response(200,json={'status':'success','data':{'screenshot':{'url':'https://iad.microlink.io/capture.png','width':1280,'height':800}}})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result=await previews().capture_preview('https://www.python.org/',client=client,resolver=public_resolver)
        assert result['status']=='available' and result['source']=='Microlink'
        assert result['captured_at'] is None and 'cached' in result['note'].lower()
    asyncio.run(run())


def test_quota_falls_back_to_exact_archived_scan_and_retains_scan_date():
    def handler(request):
        if request.url.host=='api.microlink.io':return httpx.Response(429)
        return httpx.Response(200,json={'results':[{'_id':'12345678-1234-1234-1234-123456789abc','page':{'url':'https://www.python.org/'},'task':{'time':'2026-11-01T12:00:00Z'}}]})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result=await previews().capture_preview('https://www.python.org/',client=client,resolver=public_resolver)
        assert result['source']=='urlscan.io archive' and result['captured_at']=='2026-11-01T12:00:00Z'
        assert result['kind']=='archived'
    asyncio.run(run())


def test_untrusted_screenshot_url_is_not_embedded_and_no_result_is_not_fabricated():
    def handler(request):
        if request.url.host=='api.microlink.io':return httpx.Response(200,json={'status':'success','data':{'screenshot':{'url':'http://127.0.0.1/image'}}})
        return httpx.Response(200,json={'results':[]})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result=await previews().capture_preview('https://www.python.org/',client=client,resolver=public_resolver)
        assert result['status']=='unavailable' and result.get('url') is None
    asyncio.run(run())


def test_preview_rejects_private_targets_before_provider_request():
    async def run():
        def handler(request):raise AssertionError('Unsafe target was sent to provider')
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result=await previews().capture_preview('http://127.0.0.1/',client=client)
        assert result['status']=='unavailable'
    asyncio.run(run())
