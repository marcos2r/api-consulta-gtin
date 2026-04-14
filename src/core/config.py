import redis.asyncio as redis
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    certificado_caminho: str
    certificado_senha: str
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

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()

redis_client = redis.from_url(settings.redis_url, decode_responses=True)
