import asyncio
import importlib

import httpx
import pytest


def module():
    return importlib.import_module('urlscan_studio.inspection')


def test_public_connection_pins_validated_address():
    async def run():
        calls=[]
        async def resolver(host,port):
            assert host=='example.com';return ['93.184.216.34']
        class Backend:
            async def connect_tcp(self,host,port,**kwargs):
                calls.append((host,port));return 'stream'
        backend=module().PublicNetworkBackend(resolver=resolver,backend=Backend())
        assert await backend.connect_tcp('example.com',443)=='stream'
        assert calls==[('93.184.216.34',443)]
    asyncio.run(run())


@pytest.mark.parametrize('addresses', [['127.0.0.1'],['10.0.0.1'],['169.254.169.254'],['::1'],['93.184.216.34','192.168.1.1']])
def test_mixed_or_private_dns_is_rejected(addresses):
    async def run():
        async def resolver(host,port):return addresses
        class Backend:
            async def connect_tcp(self,*args,**kwargs):pytest.fail('Unsafe destination was contacted')
        with pytest.raises(module().UnsafeTarget):
            await module().PublicNetworkBackend(resolver=resolver,backend=Backend()).connect_tcp('example.com',443)
    asyncio.run(run())


@pytest.mark.parametrize('url',['http://127.1/','http://2130706433/','http://localhost/','https://example.com:8443/','file:///etc/passwd','https://user:pass@example.com/'])
def test_unsafe_or_non_web_targets_are_blocked(url):
    with pytest.raises(ValueError):module().validate_target(url)


def test_analysis_returns_actionable_evidence_and_no_malware_claim():
    m=module()
    result=m.analyse_response('http://example.com/','https://example.com/',200,
        {'content-type':'text/html','x-content-type-options':'nosniff'},
        '<html><title>Example &amp; Co</title><script src="https://cdn.example.net/a.js"></script></html>',
        120,[{'url':'http://example.com/','status':301},{'url':'https://example.com/','status':200}],False)
    assert result['title']=='Example & Co'
    assert result['source']=='live-http' and result['verdict']!='malicious'
    assert any('Content Security Policy' in f['title'] for f in result['findings'])
    assert result['posture']['passed'] < result['posture']['total']
    assert result['resource_references'][0]['host']=='cdn.example.net'
    assert len(result['requests'])==2


def test_complete_headers_have_full_baseline_coverage():
    r=module().analyse_response('https://example.com/','https://example.com/',200,
        {'content-type':'text/html','strict-transport-security':'max-age=31536000',
         'content-security-policy':"default-src 'self'; frame-ancestors 'none'",'x-content-type-options':'nosniff',
         'referrer-policy':'strict-origin-when-cross-origin','permissions-policy':'camera=()'},'<title>OK</title>',80,
        [{'url':'https://example.com/','status':200}],False)
    assert r['posture']['passed']==r['posture']['total']
    assert r['verdict']=='no_flags'


def test_redirect_to_internal_target_never_requested():
    calls=[]
    def handler(request):
        calls.append(str(request.url));return httpx.Response(302,headers={'location':'http://127.0.0.1/admin'})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result=await module().inspect_url('https://example.com/',client=client)
        assert result['status']=='failed' and 'public' in result['error'].lower()
        assert calls==['https://example.com/']
    asyncio.run(run())


def test_redirect_loop_and_timeout_are_unknown_not_clean():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req:httpx.Response(302,headers={'location':'/'}))) as client:
            result=await module().inspect_url('https://example.com/',client=client)
            assert result['status']=='failed' and result['result'] is None
        def timeout(request):raise httpx.ReadTimeout('private error detail',request=request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(timeout)) as client:
            result=await module().inspect_url('https://example.com/',client=client)
            assert result['status']=='failed' and 'private error' not in result['error']
    asyncio.run(run())


def test_body_limit_reports_incomplete_coverage():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req:httpx.Response(200,headers={'content-type':'text/html'},content=b'x'*600000))) as client:
            item=await module().inspect_url('https://example.com/',client=client)
            assert item['status']=='completed' and item['result']['body_truncated'] is True
    asyncio.run(run())


def test_malformed_reference_does_not_discard_valid_http_evidence():
    result=module().analyse_response('https://example.com/','https://example.com/',200,
        {'content-type':'text/html'},'<title>Still useful</title><img src="http://[broken">',12,
        [{'url':'https://example.com/','status':200}],False)
    assert result['title']=='Still useful' and result['http_status']==200
    assert result['resource_references']==[]


def test_unrestricted_framing_is_not_reported_as_protection():
    result=module().analyse_response('https://example.com/','https://example.com/',200,
        {'content-type':'text/html','content-security-policy':'frame-ancestors *','x-frame-options':'DENY'},'',12,
        [{'url':'https://example.com/','status':200}],False)
    assert next(check for check in result['checks'] if check['id']=='framing')['passed'] is False


def test_malformed_http_is_reported_as_failed_not_an_api_error():
    import httpcore
    def handler(request):raise httpcore.RemoteProtocolError('sensitive upstream detail')
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result=await module().inspect_url('https://example.com/',client=client)
            assert result['status']=='failed' and 'sensitive' not in result['error']
    asyncio.run(run())
