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

def test_consultar_gtin_sefaz_mockado(client, mock_sefaz_success, mocker):
    """Verifica se a rota responde corretamente quando a SEFAZ encontra o produto."""
    # Mock do EANdata preservando o dict_retorno da SEFAZ
    async def mock_enriquecer(gtin, dict_retorno):
        dict_retorno["eandata"] = {"status": {"code": "200"}, "product": {}}
        return dict_retorno
    mocker.patch("src.use_cases.consultar_gtin.enriquecer_com_eandata", side_effect=mock_enriquecer)
    
    # Bypass na validação do GTIN para facilitar o teste com qualquer código válido estruturalmente
    mocker.patch("src.use_cases.consultar_gtin.validate_gtin", return_value=True)
    
    response = client.get("/gtin/7891234567890")
    
    # 200 Indica que a chamada não explodiu e encontrou algo
    assert response.status_code == 200
