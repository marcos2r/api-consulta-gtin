import pytest
from src.utils.helpers import validate_gtin

def test_health_check(client):
    """Verifica se o endpoint de health probe está online."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_consultar_gtin_invalido(client):
    """Verifica se a API rejeita GTINs com tamanho ou dígito verificador incorretos."""
    response = client.get("/gtin/123")
    assert response.status_code == 400
    assert "inválido" in response.json()["detail"].lower()

def test_consultar_gtin_sefaz_mockado(client, mock_redis, mock_sefaz_success, mocker):
    """Verifica se a rota responde corretamente quando a SEFAZ encontra o produto."""
    # Mock do EANdata para não fazer requisição real durante o teste
    mocker.patch("src.services.eandata_client.enriquecer_com_eandata", return_value={"mock": "data"})
    
    # Bypass na validação do GTIN para facilitar o teste com qualquer código válido estruturalmente
    mocker.patch("src.api.routes.validate_gtin", return_value=True)
    
    response = client.get("/gtin/7891234567890")
    
    # 200 Indica que a chamada não explodiu e encontrou algo
    assert response.status_code == 200
