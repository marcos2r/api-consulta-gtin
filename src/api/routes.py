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
            dict_retorno = enriquecer_com_eandata(codigo_gtin, dict_retorno)
            logger.info(f"Consulta finalizada com sucesso para GTIN: {codigo_gtin}")
            return formatar_resposta_personalizada(dict_retorno, codigo_gtin)
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
    return {"status": "ok", "message": "API de consulta GTIN está operante."}
