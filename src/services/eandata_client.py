import requests
import json
from src.core.logging_setup import logger
from src.core.config import settings

def enriquecer_com_eandata(codigo_gtin: str, dict_retorno: dict) -> dict:
    try:
        api_key = settings.eandata_api_key
        base_url = settings.eandata_url

        if not api_key or not base_url:
            logger.warning("Credenciais da EANdata não configuradas. Pulando enriquecimento.")
            return dict_retorno

        url = f"{base_url}?keycode={api_key}&mode=json&find={codigo_gtin}"
        
        response = requests.get(url, timeout=10)
        
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
