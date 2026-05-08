from fastapi import APIRouter, HTTPException
import xmltodict
import traceback

from src.core.logging_setup import logger
from src.core.config import settings
from src.utils.helpers import validate_gtin
from src.utils.formatters import formatar_resposta_personalizada, formatar_resposta_bluesoft
from src.services.sefaz_client import consultar_gtin_pfx_cached_async
from src.services.bluesoft_client import consultar_bluesoft_cosmos
from src.services.eandata_client import enriquecer_com_eandata

router = APIRouter()

@router.get("/gtin/{codigo_gtin}", summary="Consulta Dados do GTIN", response_description="Retorna dados detalhados do GTIN")
async def consultar_gtin(codigo_gtin: str):
    """Rota principal para consulta de informações de produtos por código GTIN/EAN.
    
    Tenta primeiramente consultar a base da SEFAZ. Caso não encontre ou a base esteja
    indisponível (via Circuit Breaker ou erro de rede), realiza fallback automático para
    a API da Bluesoft Cosmos. Os dados de ambas as fontes são potencialmente enriquecidos
    pela base da EANdata.
    
    Args:
        codigo_gtin (str): Código GTIN/EAN numérico com 8, 12, 13 ou 14 dígitos.
        
    Returns:
        dict: Resposta formatada no padrão NF-e com os dados do produto.
        
    Raises:
        HTTPException(400): Se o código GTIN for inválido.
        HTTPException(404): Se o produto não for encontrado nem na SEFAZ nem na Bluesoft.
        HTTPException(500): Falhas sistêmicas irrecuperáveis.
    """
    logger.info(f"Nova requisição de consulta recebida para GTIN: {codigo_gtin}")
    if not validate_gtin(codigo_gtin):
        logger.warning(f"GTIN inválido recebido: {codigo_gtin}")
        raise HTTPException(status_code=400, detail="Código GTIN inválido. Verifique o tamanho e o dígito verificador.")

    pfx_file = settings.certificado_caminho
    pfx_password = settings.certificado_senha

    try:
        xml_retorno = await consultar_gtin_pfx_cached_async(codigo_gtin, pfx_file, pfx_password)
        if xml_retorno:
            dict_retorno = xmltodict.parse(xml_retorno)
            dict_retorno = await enriquecer_com_eandata(codigo_gtin, dict_retorno)
            resposta_sefaz = formatar_resposta_personalizada(dict_retorno, codigo_gtin)
            
            if resposta_sefaz.get("status") == "success":
                logger.info(f"Consulta finalizada com sucesso para GTIN na SEFAZ: {codigo_gtin}")
                return resposta_sefaz
            else:
                logger.warning(f"SEFAZ não encontrou o produto (cStat: {resposta_sefaz.get('cStat')}). Executando fallback Cosmos.")
        else:
            logger.warning(f"Resposta vazia da SEFAZ para GTIN: {codigo_gtin}. Executando fallback Cosmos.")
    except Exception as e:
        logger.error(f"Erro na consulta SEFAZ para GTIN {codigo_gtin}: {str(e)}")
        logger.debug(traceback.format_exc())

    logger.info(f"Tentando consulta via Bluesoft Cosmos para GTIN: {codigo_gtin}")
    try:
        dados_bluesoft = await consultar_bluesoft_cosmos(codigo_gtin)
        if dados_bluesoft:
            logger.info(f"Consulta Bluesoft Cosmos bem-sucedida para GTIN: {codigo_gtin}")
            return formatar_resposta_bluesoft(dados_bluesoft, codigo_gtin)
        else:
            logger.warning(f"GTIN não encontrado na SEFAZ e na Bluesoft Cosmos: {codigo_gtin}")
            raise HTTPException(status_code=404, detail="GTIN não encontrado nas bases de dados consultadas.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro na consulta Bluesoft Cosmos para GTIN {codigo_gtin}: {str(e)}")
        logger.debug(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Erro interno ao processar a requisição: {str(e)}")

@router.get("/health", summary="Verificação de Saúde")
def health_check():
    """Rota de Liveness/Readiness Probe para verificação de status da API.
    
    Returns:
        dict: Status de operação atual do microsserviço.
    """
    return {"status": "ok", "message": "API de consulta GTIN está operante."}
