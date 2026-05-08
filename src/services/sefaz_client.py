import re
import asyncio
import hashlib
import logging
import requests
import time
from requests_pkcs12 import Pkcs12Adapter
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_sleep_log

from src.core.logging_setup import logger
from src.core.config import settings, redis_client

class CircuitBreaker:
    """Implementa o padrão Circuit Breaker para evitar chamadas contínuas a serviços inativos.
    
    Attributes:
        failures_allowed (int): Número de falhas consecutivas permitidas antes de abrir o circuito.
        reset_timeout (int): Tempo em segundos para o circuito permanecer aberto.
        failures (int): Contador atual de falhas consecutivas.
        last_failure_time (float): Timestamp da última falha.
        state (str): Estado atual do circuito ('CLOSED', 'OPEN', 'HALF_OPEN').
    """
    def __init__(self, failures_allowed: int = 3, reset_timeout: int = 60):
        """Inicializa o Circuit Breaker.
        
        Args:
            failures_allowed (int, optional): Máximo de falhas permitidas. Padrão é 3.
            reset_timeout (int, optional): Tempo de bloqueio em segundos. Padrão é 60.
        """
        self.failures_allowed = failures_allowed
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure_time = None
        self.state = "CLOSED"

    def can_execute(self) -> bool:
        """Verifica se a requisição pode ser executada com base no estado do circuito.
        
        Returns:
            bool: True se o circuito está fechado ou meio-aberto, False se aberto.
        """
        if self.state == "CLOSED":
            return True
        
        if self.state == "OPEN":
            if time.time() - self.last_failure_time >= self.reset_timeout:
                self.state = "HALF_OPEN"
                logger.info("Circuit Breaker: Estado alterado para HALF_OPEN")
                return True
            return False
            
        return True # HALF_OPEN

    def record_failure(self):
        """Registra uma falha e atualiza o estado do circuito se necessário."""
        self.failures += 1
        self.last_failure_time = time.time()
        if self.failures >= self.failures_allowed:
            self.state = "OPEN"
            logger.warning(f"Circuit Breaker: Estado alterado para OPEN. Falhas: {self.failures}")

    def record_success(self):
        """Registra um sucesso e reseta o circuito para fechado."""
        if self.state != "CLOSED":
            logger.info("Circuit Breaker: Estado alterado para CLOSED")
        self.failures = 0
        self.state = "CLOSED"

circuit_breaker = CircuitBreaker()

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception),
    reraise=True,
    before_sleep=before_sleep_log(logger, logging.ERROR),
)
def consultar_gtin_pfx(gtin: str, pfx_file: str, pfx_password: str) -> str:
    """Realiza consulta síncrona ao webservice da SEFAZ utilizando requisição SOAP e certificado digital PFX.
    
    Esta função utiliza `tenacity` para realizar tentativas (retries) em caso de falha na requisição.
    
    Args:
        gtin (str): Código GTIN/EAN do produto a ser consultado.
        pfx_file (str): Caminho absoluto para o arquivo de certificado digital (.pfx).
        pfx_password (str): Senha do certificado digital.
        
    Returns:
        str: Resposta XML do webservice da SEFAZ em formato string.
        
    Raises:
        Exception: Se todas as tentativas falharem ou ocorrer um erro de rede.
    """
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
    """Consulta o webservice da SEFAZ com verificação no Redis Cache e proteção de Circuit Breaker.
    
    A chamada ao webservice é encapsulada em um ThreadPoolExecutor para evitar bloqueio do Event Loop,
    já que `requests` é síncrono.
    
    Args:
        gtin (str): Código GTIN/EAN do produto.
        pfx_file (str): Caminho para o arquivo do certificado PFX.
        pfx_password (str): Senha do certificado digital.
        
    Returns:
        str: Conteúdo XML da SEFAZ, seja proveniente do cache ou da chamada em tempo real.
        
    Raises:
        Exception: Quando a SEFAZ falha persistentemente ou o Circuit Breaker está aberto.
    """
    if not circuit_breaker.can_execute():
        logger.warning(f"Circuit Breaker ABERTO. Interrompendo chamada para SEFAZ (GTIN: {gtin}).")
        raise Exception("Circuit Breaker ABERTO: Serviço SEFAZ inoperante no momento.")

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
    try:
        result = await loop.run_in_executor(None, consultar_gtin_pfx, gtin, pfx_file, pfx_password)
        circuit_breaker.record_success()
    except Exception as e:
        circuit_breaker.record_failure()
        raise e
    
    try:
        await redis_client.setex(cache_key, 3600, result)
    except Exception as e:
        logger.warning(f"Erro ao salvar no cache do Redis: {e}")
        
    return result
