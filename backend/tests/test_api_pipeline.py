import io
import time

from fastapi.testclient import TestClient

from app.main import app


def test_models_endpoint_returns_availability():
    with TestClient(app) as client:
        response = client.get('/api/models')
        assert response.status_code == 200
        payload = response.json()
        names = {item['name'] for item in payload['models']}
        assert {'llama_ollama', 'mistral', 'openai_gpt4_1', 'anthropic_claude'}.issubset(names)


def test_full_netflow_csv_pipeline():
    csv_content = (
        'src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,start_ts,end_ts\n'
        '8.8.8.8,10.0.0.10,34567,443,tcp,20,2048,2026-01-01T00:00:00Z,2026-01-01T00:00:02Z\n'
    )

    with TestClient(app) as client:
        upload_res = client.post(
            '/api/uploads',
            files={'file': ('sample.csv', io.BytesIO(csv_content.encode('utf-8')), 'text/csv')},
        )
        assert upload_res.status_code == 200
        upload_id = upload_res.json()['upload_id']

        parse_res = client.post(f'/api/uploads/{upload_id}/parse')
        assert parse_res.status_code == 200
        assert parse_res.json()['flows_count'] == 1

        scenario_res = client.post(f'/api/uploads/{upload_id}/scenario')
        assert scenario_res.status_code == 200

        run_res = client.post(
            '/api/runs',
            json={'upload_id': upload_id, 'models': ['llama_ollama'], 'repeats': 1},
        )
        assert run_res.status_code == 200
        run_id = run_res.json()['run_id']

        for _ in range(20):
            detail_res = client.get(f'/api/runs/{run_id}')
            assert detail_res.status_code == 200
            payload = detail_res.json()
            if payload['status'] == 'completed':
                break
            time.sleep(0.2)
        else:
            raise AssertionError('Run did not complete in expected time')

        export_res = client.get(f'/api/runs/{run_id}/export.zip')
        assert export_res.status_code == 200
        assert export_res.headers['content-type'].startswith('application/zip')
