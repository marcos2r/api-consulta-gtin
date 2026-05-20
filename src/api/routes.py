from fastapi import APIRouter, Depends, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from src.use_cases.consultar_gtin import ConsultarGtinUseCase
from src.schemas.produto import ProdutoResponse
from src.repositories.produto_repo import produto_repository
from src.core.limiter import limiter
from src.core.security import verificar_api_key_soft
from src.schemas.api_key import ApiKeyBase

router = APIRouter()

def get_consultar_gtin_use_case() -> ConsultarGtinUseCase:
    """Injeção de dependência para instanciar o Use Case."""
    return ConsultarGtinUseCase(produto_repo=produto_repository)

@router.get(
    "/gtin/{codigo_gtin}", 
    summary="Consulta Dados do GTIN", 
    response_description="Retorna dados detalhados do GTIN",
    response_model=ProdutoResponse
)
@limiter.limit("100/minute")
async def consultar_gtin(
    request: Request,
    codigo_gtin: str, 
    background_tasks: BackgroundTasks,
    use_case: ConsultarGtinUseCase = Depends(get_consultar_gtin_use_case),
    api_key: ApiKeyBase | None = Depends(verificar_api_key_soft)
):
    """Rota principal para consulta de informações de produtos por código GTIN/EAN.
    
    A orquestração completa ocorre na camada de Use Cases.
    
    Args:
        codigo_gtin (str): Código GTIN/EAN numérico com 8, 12, 13 ou 14 dígitos.
        background_tasks (BackgroundTasks): Injeção do gerenciador de tasks do FastAPI.
        use_case (ConsultarGtinUseCase): Instância do caso de uso injetada via FastAPI Depends.
        
    Returns:
        ProdutoResponse: Resposta formatada e tipada com os dados do produto.
    """
    resultado = await use_case.executar(codigo_gtin, background_tasks)
    
    # Soft Rollout: se for dict, injeta o aviso
    if getattr(request.state, "auth_warning", False):
        mensagem_aviso = "ATENÇÃO: A autenticação via header X-API-Key se tornará obrigatória em breve. Adeque sua aplicação."
        if isinstance(resultado, dict):
            resultado["aviso_depreciacao"] = mensagem_aviso
        elif isinstance(resultado, JSONResponse):
            import json
            body = json.loads(resultado.body.decode("utf-8"))
            body["aviso_depreciacao"] = mensagem_aviso
            # Evitamos repassar headers de controle como content-length e content-type originais.
            # Ao limpá-los, permitimos que o Starlette recalcule o tamanho correto da nova payload,
            # eliminando inconsistências que causam HTTP 502 em proxies estritos (como o Google Frontend).
            headers_limpos = {
                k: v for k, v in resultado.headers.items() 
                if k.lower() not in ["content-length", "content-type"]
            }
            return JSONResponse(
                status_code=resultado.status_code, 
                content=body, 
                headers=headers_limpos
            )
            
    return resultado

@router.get("/health", summary="Verificação de Saúde")
async def health_check():
    """Rota de Liveness/Readiness Probe para verificação de status da API.
    
    Verifica a saúde da API e a conectividade detalhada com o banco de dados Firestore.
    
    Returns:
        dict: Status de operação atual e detalhes do erro se houver.
    """
    try:
        db_ok, error = await produto_repository.test_connection()
        if db_ok:
            return {
                "status": "ok",
                "message": "API de consulta GTIN está operante.",
                "database": "online"
            }
        else:
            return {
                "status": "degraded",
                "database": "offline",
                "message": "Falha na conexão com Firestore.",
                "detail": error
            }
    except Exception as e:
        return {
            "status": "error",
            "database": "offline",
            "detail": str(e)
        }
