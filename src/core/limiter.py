from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

def get_limiter_key(request: Request) -> str:
    """Extrai a chave para o Rate Limiting.
    Prioriza a chave de API (se existir), caso contrário usa o IP do cliente.
    """
    if hasattr(request.state, "api_key") and request.state.api_key:
        return request.state.api_key.key_id
    return get_remote_address(request)

# Inicialização do Rate Limiter
limiter = Limiter(key_func=get_limiter_key)
