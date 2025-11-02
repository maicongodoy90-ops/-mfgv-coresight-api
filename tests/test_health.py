def test_basic():
    assert 1 + 1 == 2

# Teste de saúde da API
import requests

def test_health_api():
    url = "https://mfgv-coresight-api.onrender.com/"
    resp = requests.get(url)
    assert resp.status_code == 200
    assert "CoreSight" in resp.text
