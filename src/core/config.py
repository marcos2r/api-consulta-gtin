import redis.asyncio as redis
import base64
import os
import tempfile
from pydantic_settings import BaseSettings, SettingsConfigDict
import logging
logger = logging.getLogger("gtin-api")

class Settings(BaseSettings):
    certificado_caminho: str | None = None
    certificado_senha: str | None = None
    certificado_base64: str | None = None
    eandata_api_key: str | None = None
    eandata_url: str | None = None
    cosmos_api_token: str | None = None
    redis_url: str = "redis://localhost:6379/0"
    ambiente: str = "producao"
    ignorar_ssl: bool = False
    contato_nome: str = "Suporte Técnico"
    contato_email: str = "suporte@exemplo.com"
    empresa_nome: str = "Empresa"
    
    # Campos adicionais encontrados no .env
    ignorar_ssl_sefaz: bool = False  
    sefaz_api_url: str = "https://dfe-portal.svrs.rs.gov.br/ws/ccgConsGTIN/ccgConsGTIN.asmx"
    cosmos_api_token_1: str | None = None
    cosmos_api_token_2: str | None = None
    cosmos_api_token_3: str | None = None
    cosmos_api_token_4: str | None = None
    cosmos_api_token_5: str | None = None
    cors_origins: str = "*"
    allowed_hosts: str = "localhost"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

# Tratamento do certificado base64 (GCP Secret Manager)
if settings.certificado_base64:
    try:
        temp_cert_path = os.path.join(tempfile.gettempdir(), "cert_gcp.pfx")
        cert_data = base64.b64decode(settings.certificado_base64)
        with open(temp_cert_path, "wb") as f:
            f.write(cert_data)
        settings.certificado_caminho = temp_cert_path
        logger.info("Certificado digital carregado a partir de Base64 e salvo temporariamente.")
    except Exception as e:
        logger.error(f"Erro ao processar certificado_base64: {str(e)}")

# Cliente Redis (Lazy connection)
redis_client = redis.from_url(settings.redis_url, decode_responses=True)
