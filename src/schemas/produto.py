from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class ProdutoDimensoes(BaseModel):
    largura: Optional[float] = None
    altura: Optional[float] = None
    comprimento: Optional[float] = None
    unidade: Optional[str] = None

class ProdutoInfoAdicional(BaseModel):
    xMarca: Optional[str] = None
    xCategoria: Optional[str] = None
    urlImagem: Optional[str] = None
    unidComercial: Optional[str] = None
    dimensoes: Optional[ProdutoDimensoes] = None
    pesoLiquido: Optional[float] = None
    pesoBruto: Optional[float] = None
    xDesc: Optional[str] = None
    xOrigem: Optional[str] = None

class ProdutoDetails(BaseModel):
    GTIN: str
    tpGTIN: Optional[str] = None
    xProd: str
    NCM: Optional[str] = None
    CEST: Optional[str] = None
    fonte: str
    atualizado: Optional[bool] = None
    infoAdicional: Optional[ProdutoInfoAdicional] = None

class ProdutoResponse(BaseModel):
    status: str
    provider: str = "PAIRUS Soluções Tecnológicas"
    timestamp: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    cStat: Optional[str] = None
    xMotivo: Optional[str] = None
    produto: Optional[ProdutoDetails] = None
