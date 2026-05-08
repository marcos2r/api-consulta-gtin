import httpx
import json
from src.core.logging_setup import logger
from src.core.config import settings

async def enriquecer_com_eandata(codigo_gtin: str, dict_retorno: dict) -> dict:
    """Consulta a API da EANdata para enriquecer os dados do produto com informações extras.
    
    Esta função realiza uma requisição GET assíncrona para a base da EANdata. Se a consulta for
    bem-sucedida, os dados extras são anexados ao `dict_retorno` sob a chave 'eandata'.
    
    Args:
        codigo_gtin (str): Código GTIN/EAN do produto.
        dict_retorno (dict): Dicionário de dados base do produto (retornado pela SEFAZ ou Bluesoft).
        
    Returns:
        dict: O mesmo `dict_retorno` recebido, modificado para incluir dados da EANdata se encontrados.
    """
    try:
        api_key = settings.eandata_api_key
        base_url = settings.eandata_url

        if not api_key or not base_url:
            logger.warning("Credenciais da EANdata não configuradas. Pulando enriquecimento.")
            return dict_retorno

        url = f"{base_url}?keycode={api_key}&mode=json&find={codigo_gtin}"
        
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url)
            
            if response.status_code == 200:
                try:
                    dados_eandata = response.json()
                    if "status" in dados_eandata and str(dados_eandata["status"].get("code")) in ["200", "500"]:
                        logger.info(f"Enriquecimento com EANdata bem-sucedido para o GTIN: {codigo_gtin}")
                        dict_retorno["eandata"] = dados_eandata
                    else:
                        logger.warning(f"EANdata retornou formato inesperado para GTIN {codigo_gtin}: {dados_eandata}")
                except json.JSONDecodeError:
                    logger.warning(f"Resposta inválida (não JSON) da EANdata para GTIN: {codigo_gtin}")
            else:
                logger.warning(f"EANdata retornou status {response.status_code} para GTIN: {codigo_gtin}")

    except Exception as e:
        logger.error(f"Erro no enriquecimento com EANdata: {str(e)}")

    return dict_retorno
