import re
import asyncio
import hashlib
import logging
import requests
from requests_pkcs12 import Pkcs12Adapter
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_sleep_log

from src.core.logging_setup import logger
from src.core.config import settings, redis_client

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception),
    reraise=True,
    before_sleep=before_sleep_log(logger, logging.ERROR),
)
def consultar_gtin_pfx(gtin: str, pfx_file: str, pfx_password: str) -> str:
    url = settings.sefaz_api_url
    gtin_seguro = re.sub(r'[^\d]', '', gtin)
    
    soap_envelope = f'<?xml version="1.0" encoding="UTF-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap12:Header/><soap12:Body><ccgConsGTIN xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin"><nfeDadosMsg><consGTIN versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe"><GTIN>{gtin_seguro}</GTIN></consGTIN></nfeDadosMsg></ccgConsGTIN></soap12:Body></soap12:Envelope>'
    
    headers = {
        "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin/ccgConsGTIN"'
    }
    
    session = requests.Session()
    session.mount('https://', Pkcs12Adapter(pkcs12_filename=pfx_file, pkcs12_password=pfx_password))
    
    verify_ssl = True
    if settings.ignorar_ssl_sefaz or (settings.ambiente == "desenvolvimento" and settings.ignorar_ssl):
        verify_ssl = False
        logger.warning("Verificação SSL desabilitada para SEFAZ - Use com cautela em produção")
    
    try:
        response = session.post(url, data=soap_envelope.encode("utf-8"),
                              headers=headers, verify=verify_ssl, timeout=30)
        response.raise_for_status()
        return response.text
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro na requisição ao webservice: {str(e)}")
        raise Exception(f"Erro na consulta ao webservice: {str(e)}")
    finally:
        session.close()

async def consultar_gtin_pfx_cached_async(gtin: str, pfx_file: str, pfx_password: str) -> str:
    key_parts = ["consultar_gtin_pfx", gtin, pfx_file, pfx_password]
    key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
    cache_key = f"cache:gtin:{key}"
    
    try:
        cached_result = await redis_client.get(cache_key)
        if cached_result:
            logger.info(f"CACHE HIT (Redis) para GTIN: {gtin}")
            return cached_result
    except Exception as e:
        logger.warning(f"Erro ao acessar cache no Redis: {e}")
        
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, consultar_gtin_pfx, gtin, pfx_file, pfx_password)
    
    try:
        await redis_client.setex(cache_key, 3600, result)
    except Exception as e:
        logger.warning(f"Erro ao salvar no cache do Redis: {e}")
        
    return result
