from fastapi import FastAPI
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

from src.core.logging_setup import logger, limpar_logs_antigos
from src.core.config import settings
from src.api.routes import router as api_router
from src.repositories.produto_repo import produto_repository

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Inicializando API de consulta GTIN")
    limpar_logs_antigos(30)
    
    # Teste de conexão com o banco no startup
    db_ok, _ = await produto_repository.test_connection()
    if db_ok:
        logger.info("Verificação de banco de dados: ONLINE")
    else:
        logger.error("Verificação de banco de dados: OFFLINE")
        
    yield
    logger.info("Encerrando API de consulta GTIN")

app = FastAPI(
    title="API de Consulta GTIN",
    description="API para consulta de produtos via GTIN/EAN",
    version="1.0.0",
    lifespan=lifespan,
    contact={
        "name": settings.contato_nome,
        "email": settings.contato_email,
        "empresa": settings.empresa_nome,
    },
    docs_url="/docs",
    redoc_url="/redoc",
)

if settings.cors_origins:
    origins = [origin.strip() for origin in settings.cors_origins.split(",")]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router)

@app.get("/", tags=["Documentação"])
def root():
    return {
        "api": "API de Consulta GTIN",
        "status": "Online",
        "docs": "/docs",
        "health": "/health",
        "provider": settings.empresa_nome
    }
