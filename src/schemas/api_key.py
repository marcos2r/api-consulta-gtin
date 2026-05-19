from pydantic import BaseModel, Field
from datetime import datetime

class ApiKeyBase(BaseModel):
    """Modelo base para chaves de API."""
    key_id: str = Field(..., description="ID/Hash da chave de API")
    client_name: str = Field(..., description="Nome do cliente/empresa consumidora")
    is_active: bool = Field(default=True, description="Status da chave")
    rate_limit: str = Field(default="100/minute", description="Limite de requisições no formato slowapi (ex: 100/minute, 10/second)")
    tier: str = Field(default="basic", description="Plano do cliente (ex: basic, pro, enterprise)")
    created_at: datetime | None = None
    last_used_at: datetime | None = None
