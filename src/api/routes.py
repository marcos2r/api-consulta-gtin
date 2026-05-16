from fastapi import APIRouter, Depends, BackgroundTasks

from src.use_cases.consultar_gtin import ConsultarGtinUseCase
from src.repositories.produto_repo import produto_repository
from src.schemas.produto import ProdutoResponse

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
async def consultar_gtin(
    codigo_gtin: str, 
    background_tasks: BackgroundTasks,
    use_case: ConsultarGtinUseCase = Depends(get_consultar_gtin_use_case)
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
    return await use_case.executar(codigo_gtin, background_tasks)

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
