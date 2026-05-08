import pytest
from fastapi.testclient import TestClient
from src.main import app

@pytest.fixture
def client():
    """Fixture que fornece um TestClient do FastAPI para as rotas."""
    return TestClient(app)

@pytest.fixture
def mock_redis(mocker):
    """Moka o cliente Redis para evitar dependência de banco de dados nos testes."""
    mock_redis_client = mocker.AsyncMock()
    mock_redis_client.get.return_value = None
    mocker.patch("src.services.sefaz_client.redis_client", mock_redis_client)
    mocker.patch("src.core.config.redis_client", mock_redis_client)
    return mock_redis_client

@pytest.fixture
def mock_sefaz_success(mocker):
    """Moka um retorno de sucesso da SEFAZ."""
    xml_mock = '''<?xml version="1.0" encoding="utf-8"?>
    <retConsGTIN xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">
        <cStat>135</cStat>
        <xMotivo>GTIN Localizado com Sucesso</xMotivo>
        <GTIN>7891234567890</GTIN>
    </retConsGTIN>'''
    return mocker.patch("src.services.sefaz_client.consultar_gtin_pfx", return_value=xml_mock)
