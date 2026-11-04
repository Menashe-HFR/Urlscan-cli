import importlib

from fastapi.testclient import TestClient


def cloud():
    return importlib.import_module('urlscan_studio.cloud')


def test_cloud_serves_real_capabilities_and_ui_without_database(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    with TestClient(cloud().create_cloud_app()) as client:
        config=client.get('/api/config').json()
        assert config['mode']=='cloud' and config['max_urls']==5
        assert config['history']=='browser' and config['live_http'] is True
        assert 'content="/api" name="api-base"' in client.get('/').text
        assert client.get('/api/health').json()['status']=='ok'
    assert list(tmp_path.iterdir())==[]


def test_sample_is_processed_by_api_and_keeps_synthetic_provenance():
    with TestClient(cloud().create_cloud_app()) as client:
        response=client.post('/api/inspect',json={'mode':'sample','name':'Sample test','urls':['https://atlas.test/','https://offline.test/']})
        assert response.status_code==200
        job=response.json()
        assert job['status']=='completed_with_errors'
        assert job['items'][0]['result']['source']=='synthetic'
        assert job['items'][1]['status']=='failed'


def test_live_batch_isolates_errors_and_deduplicates(monkeypatch):
    async def inspect(url):
        if 'unavailable' in url:return {'url':url,'status':'failed','result':None,'error':'Timeout','cached':False}
        return {'url':url,'status':'completed','result':{'source':'live-http','verdict':'review'},'error':None,'cached':False}
    monkeypatch.setattr(cloud(),'inspect_url',inspect)
    with TestClient(cloud().create_cloud_app()) as client:
        job=client.post('/api/inspect',json={'urls':['https://example.com/','https://EXAMPLE.com','https://unavailable.test/']}).json()
        assert job['duplicates']==1 and job['total']==2
        assert job['items'][0]['result']['source']=='live-http'
        assert job['status']=='completed_with_errors'


def test_cloud_rejects_unsafe_inputs_and_cross_origin_requests():
    with TestClient(cloud().create_cloud_app()) as client:
        assert client.post('/api/inspect',json={'urls':['http://127.0.0.1/']}).status_code==422
        assert client.post('/api/inspect',json={'urls':['https://example.com/']*6}).status_code==422
        assert client.post('/api/inspect',json={'urls':['https://example.com/']},headers={'Origin':'https://other.test'}).status_code==403
        assert client.post('/api/inspect',json={'mode':'sample','name':'  ','urls':['https://atlas.test/']}).status_code==422
