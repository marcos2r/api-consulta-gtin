from fastapi import Request, Security
from fastapi.security import APIKeyHeader

from src.repositories.api_key_repo import api_key_repository
from src.schemas.api_key import ApiKeyBase

api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verificar_api_key_soft(
    request: Request,
    api_key_header: str | None = Security(api_key_header_scheme)
) -> ApiKeyBase | None:
    """Validação Soft da Chave de API.
    
    Em vez de bloquear requisições não autenticadas (Hard Block),
    esta dependência retorna None se a chave for inválida ou ausente.
    Isso permite o Soft Rollout (Shadow Mode).
    """
    request.state.api_key = None
    request.state.auth_warning = False

    if not api_key_header:
        request.state.auth_warning = True
        return None
    
    chave = await api_key_repository.buscar_chave(api_key_header)
    
    if not chave or not chave.is_active:
        request.state.auth_warning = True
        return None
    
    request.state.api_key = chave
    return chave
