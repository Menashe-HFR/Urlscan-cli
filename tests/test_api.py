import time

import pytest
from fastapi.testclient import TestClient

from urlscan_studio.app import create_app
from urlscan_studio.providers import DemoProvider


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(str(tmp_path/"test.db"),DemoProvider(.001))) as client:
        yield client


def finish(client,job_id):
    for _ in range(100):
        job=client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in {"queued","running"}:
            return job
        time.sleep(.01)
    pytest.fail("Worker did not finish")


def test_full_api_batch_export_and_history(client):
    response=client.post('/api/jobs',json={"urls":["atlas.test","https://ATLAS.test/","https://offline.test/"]})
    assert response.status_code==202
    job_id=response.json()["id"];job=finish(client,job_id)
    assert job["duplicates"]==1 and job["total"]==2 and job["done"]==2
    assert job["status"]=="completed_with_errors"
    assert job["items"][0]["result"]["source"]=="synthetic"
    assert client.get('/api/jobs').json()["jobs"][0]["id"]==job_id
    assert 'text/csv' in client.get(f'/api/jobs/{job_id}/export').headers['content-type']
    assert 'synthetic' in client.get(f'/api/jobs/{job_id}/export').text
    assert client.get(f'/api/jobs/{job_id}/export?format=json').json()["id"]==job_id
    assert client.get(f'/api/jobs/{job_id}/export?format=exe').status_code==422
    assert client.post(f'/api/jobs/{job_id}/retry').status_code==202


def test_input_errors_and_idempotency(client):
    assert client.post('/api/jobs',json={"urls":[]}).status_code==422
    assert client.post('/api/jobs',json={"urls":["http://127.0.0.1/"]}).status_code==422
    body={"urls":["atlas.test"]};headers={"Idempotency-Key":"same-request"}
    first=client.post('/api/jobs',json=body,headers=headers).json()
    again=client.post('/api/jobs',json=body,headers=headers).json()
    assert first["id"]==again["id"] and again["created"] is False
    assert client.post('/api/jobs',json={"urls":["other.test"]},headers=headers).status_code==409
    assert client.get('/api/jobs/missing').status_code==404


def test_origin_and_host_guards(client):
    assert client.post('/api/jobs',json={"urls":["atlas.test"]},headers={"Origin":"https://other.test"}).status_code==403
    assert client.get('/api/health',headers={"Host":"other.test"}).status_code==400
    assert client.post('/api/jobs',json={"urls":["atlas.test"]},headers={"Origin":"http://testserver"}).status_code==202


def test_dashboard_api_mode_and_no_key_exposure(client):
    assert 'content="/api" name="api-base"' in client.get('/').text
    config=client.get('/api/config').json()
    assert config["synthetic"] is True and 'key' not in str(config)
    assert client.get('/openapi.json').status_code==200
