import os
import re
import time
import glob
import hashlib
import logging
import logging.config
import xmltodict
import requests
from requests_pkcs12 import Pkcs12Adapter
from functools import wraps
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import asyncio
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from fastapi import FastAPI, Depends
from pydantic_settings import BaseSettings, SettingsConfigDict

# =========================
# Configurações com Pydantic v2
# =========================
class Settings(BaseSettings):
    certificado_caminho: str
    certificado_senha: str
    eandata_api_key: str = None
    eandata_url: str = None
    cosmos_api_token: str = None
    ambiente: str = "producao"
    ignorar_ssl: bool = False
    contato_nome: str = "Suporte Técnico"
    contato_email: str = "suporte@exemplo.com"
    empresa_nome: str = "Empresa"
    
    # Campos adicionais encontrados no .env
    ignorar_ssl_sefaz: bool = False  # Modificado para permitir ignorar SSL da SEFAZ
    sefaz_api_url: str = "https://dfe-portal.svrs.rs.gov.br/ws/ccgConsGTIN/ccgConsGTIN.asmx"
    cosmos_api_token_1: str = None
    cosmos_api_token_2: str = None
    cosmos_api_token_3: str = None
    cosmos_api_token_4: str = None
    cosmos_api_token_5: str = None
    cors_origins: str = "*"
    allowed_hosts: str = "localhost"

    # Nova forma de configurar o modelo em Pydantic v2
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()

# =========================
# Configuração de Logging
# =========================
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = os.path.join(LOG_DIR, f"gtin_api_{datetime.now().strftime('%Y%m%d')}.log")

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"}
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "standard",
            "filename": log_filename,
            "maxBytes": 10 * 1024 * 1024,  # 10 MB
            "backupCount": 5,
            "level": "INFO",
        },
    },
    "loggers": {
        "gtin-api": {
            "handlers": ["file", "console"] if settings.ambiente == "desenvolvimento" else ["file"],
            "level": "INFO",
            "propagate": False,
        }
    },
}
logging.config.dictConfig(logging_config)
logger = logging.getLogger("gtin-api")

# =========================
# Utilitários e Cache
# =========================
def flexible_cache(maxsize=128, ttl=3600):
    """
    Decorador de cache simples com TTL.
    """
    cache = {}
    cache_timestamps = {}

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key_parts = [func.__name__] + [str(arg) for arg in args] + [
                f"{k}={v}" for k, v in sorted(kwargs.items())
            ]
            key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
            current_time = time.time()
            if key in cache and (current_time - cache_timestamps.get(key, 0)) < ttl:
                return cache[key]
            result = func(*args, **kwargs)
            cache[key] = result
            cache_timestamps[key] = current_time
            if len(cache) > maxsize:
                oldest_key = min(cache_timestamps, key=cache_timestamps.get)
                del cache[oldest_key]
                del cache_timestamps[oldest_key]
            return result

        return wrapper

    return decorator

def limpar_logs_antigos(dias_para_manter=30):
    """
    Remove arquivos de log com mais de 'dias_para_manter' dias.
    """
    logger.info(f"Iniciando limpeza de logs antigos (mantendo últimos {dias_para_manter} dias)")
    data_limite = datetime.now() - timedelta(days=dias_para_manter)
    padrao_arquivo = os.path.join(LOG_DIR, "gtin_api_*.log")
    arquivos_log = glob.glob(padrao_arquivo)
    contador_removidos = 0
    for arquivo in arquivos_log:
        nome_arquivo = os.path.basename(arquivo)
        try:
            data_str = nome_arquivo.replace("gtin_api_", "").replace(".log", "")
            data_arquivo = datetime.strptime(data_str, "%Y%m%d")
            if data_arquivo < data_limite:
                os.remove(arquivo)
                contador_removidos += 1
                logger.info(f"Log antigo removido: {nome_arquivo}")
        except Exception as e:
            logger.warning(f"Erro ao processar arquivo de log {nome_arquivo}: {str(e)}")
    logger.info(f"Limpeza de logs concluída. {contador_removidos} arquivos removidos.")

# =========================
# Validação de GTIN
# =========================
def validate_gtin(gtin_code: str) -> bool:
    if not isinstance(gtin_code, str) or not gtin_code.isdigit():
        return False
    if len(gtin_code) > 14 or len(gtin_code) not in [8, 12, 13, 14]:
        return False
    digito_verificador = int(gtin_code[-1])
    total = 0
    fator = 3
    for i in range(len(gtin_code) - 2, -1, -1):
        total += int(gtin_code[i]) * fator
        fator = 4 - fator  # Alterna entre 3 e 1
    digito_calculado = (10 - (total % 10)) % 10
    return digito_verificador == digito_calculado

# =========================
# Cliente SOAP para SEFAZ
# =========================
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def consultar_gtin_pfx(gtin: str, pfx_file: str, pfx_password: str) -> str:
    """
    Consulta o webservice da SEFAZ via SOAP utilizando certificado digital.
    """
    url = "https://dfe-servico.svrs.rs.gov.br/ws/ccgConsGTIN/ccgConsGTIN.asmx"
    gtin_seguro = re.sub(r'[^\d]', '', gtin)
    
    # Modificando para uma única linha sem quebras
    soap_envelope = f'<?xml version="1.0" encoding="UTF-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap12:Header/><soap12:Body><ccgConsGTIN xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin"><nfeDadosMsg><consGTIN versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe"><GTIN>{gtin_seguro}</GTIN></consGTIN></nfeDadosMsg></ccgConsGTIN></soap12:Body></soap12:Envelope>'
    
    headers = {
        "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin/ccgConsGTIN"'
    }
    session = requests.Session()
    session.mount('https://', Pkcs12Adapter(pkcs12_filename=pfx_file, pkcs12_password=pfx_password))
    verify_ssl = True
    
    # Modificado para verificar a configuração ignorar_ssl_sefaz
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

@flexible_cache(maxsize=128, ttl=3600)
def consultar_gtin_pfx_cached(gtin: str, pfx_file: str, pfx_password: str) -> str:
    return consultar_gtin_pfx(gtin, pfx_file, pfx_password)

# =========================
# Utilitário para Busca de Chaves
# =========================
def buscar_chave(dicionario: dict, chave_procurada: str):
    if not isinstance(dicionario, dict):
        return None
    pilha = [dicionario]
    while pilha:
        atual = pilha.pop()
        for chave, valor in atual.items():
            if chave == chave_procurada:
                return atual
            if isinstance(valor, dict):
                pilha.append(valor)
    return None

# =========================
# Enriquecimento com EANdata (assíncrono)
# =========================
async def enriquecer_com_eandata(dict_retorno: dict) -> dict:
    """
    Envia dados enriquecidos de um produto para a API do EANdata, de forma assíncrona.

    Essa função extrai peso e descrição do produto usando a função `weight`, e envia os campos
    formatados para a API do EANdata como atualização silenciosa, sem afetar o fluxo principal da API
    mesmo em caso de falhas.

    A requisição é feita em modo assíncrono usando httpx, evitando bloqueios de I/O na aplicação FastAPI.

    Args:
        dict_retorno (dict): Dicionário com os dados da resposta anterior (SEFAZ ou Bluesoft)

    Returns:
        dict: O mesmo dicionário recebido, inalterado na estrutura. Apenas logs são registrados.
    """

    try:
        logger.info("Iniciando enriquecimento com EANdata...")

        # Verifica se o status da resposta permite o envio
        if dict_retorno.get("status") != "success":
            logger.warning("Enriquecimento cancelado: status da resposta não é 'success'")
            return dict_retorno

        # Verifica se há configuração mínima
        url = settings.eandata_url
        keycode = settings.eandata_api_key
        produto = dict_retorno.get("produto", {})
        update = produto.get("GTIN")

        if not url or not keycode or not update:
            logger.warning("Chave, URL ou GTIN ausentes. Enriquecimento com EANdata não será realizado.")
            return dict_retorno

        # Extrai e limpa informações do produto
        resultado_peso = extrair_peso_unidade(produto.get("xProd", ""))
        campos = []

        if resultado_peso:
            descricao_limpa = resultado_peso.get("descricao")
            valor = resultado_peso.get("valor")
            unidade = resultado_peso.get("unidade")

            if descricao_limpa:
                campos.append({
                    "field": "product",
                    "value": descricao_limpa
                })
                campos.append({
                    "field": "language",
                    "value": descricao_limpa,
                    "extra_id": "659"  # Código fixo (Português-BR?)
                })

            if valor and unidade:
                campos.append({
                    "field": "weight",
                    "value": f"{valor} {unidade}"
                })

        # Se não houver o que enviar, evita chamada desnecessária
        if not campos:
            logger.info("Nenhum campo para enriquecer no EANdata.")
            return dict_retorno

        # Prepara payload
        payload = {
            "v": "3",
            "keycode": keycode,
            "update": update,
            "field": "*bulk*",
            "fields": campos
        }

        # Requisição assíncrona com httpx
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, params=payload)

            if response.status_code == 200:
                logger.info(f"Enriquecimento EANdata realizado com sucesso para GTIN: {update}")
                logger.debug(f"Resposta EANdata: {response.text}")
            else:
                logger.warning(f"EANdata retornou status {response.status_code} para GTIN: {update}")

    except Exception as e:
        logger.error(f"Erro no enriquecimento com EANdata: {str(e)}")

    # Retorna a resposta original sempre
    return dict_retorno

# =========================
# Formatação da Resposta (Padrão NF-e)
# =========================
def formatar_resposta_personalizada(dict_retorno: dict, codigo_gtin: str) -> dict:
    try:
        resposta = {
            "status": "success",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "produto": {}
        }

        ret_cons_gtin_dict = buscar_chave(dict_retorno, "retConsGTIN")
        if ret_cons_gtin_dict and "retConsGTIN" in ret_cons_gtin_dict:
            ret_cons_gtin = ret_cons_gtin_dict["retConsGTIN"]
            if ret_cons_gtin.get("xMotivo") == "Consulta realizada com sucesso":
                resposta["produto"] = {
                    "GTIN": ret_cons_gtin.get("GTIN", codigo_gtin),
                    "tpGTIN": ret_cons_gtin.get("tpGTIN", ""),
                    "xProd": ret_cons_gtin.get("xProd", "").upper(),
                    "NCM": ret_cons_gtin.get("NCM", ""),
                    "CEST": ret_cons_gtin.get("CEST", ""),
                    "fonte": "SEFAZ"
                }

                resposta["cStat"] = "100"
                resposta["xMotivo"] = "Consulta realizada com sucesso"

                # Enriquecimento EANdata
                if "eandata" in dict_retorno and "status" in dict_retorno["eandata"]:
                    eandata = dict_retorno["eandata"]
                    if eandata["status"].get("code") in ["200", "500"]:
                        resposta["produto"]["atualizado"] = True
                        if "product" in eandata and eandata["product"]:
                            produto_eandata = eandata["product"]
                            extras = {}

                            campo_mapping = {
                                "description": "xDesc",
                                "brand": "xMarca",
                                "category": "xCategoria",
                                "country": "xOrigem"
                            }
                            for campo_original, campo_nfe in campo_mapping.items():
                                if campo_original in produto_eandata and produto_eandata[campo_original]:
                                    extras[campo_nfe] = produto_eandata[campo_original]

                            # Lógica de fallback de imagem
                            ean_img_url = ""
                            try:
                                produtos_eandata = dict_retorno["eandata"].get("products", [])
                                if produtos_eandata:
                                    campos = produtos_eandata[0].get("fields", [])
                                    for campo in campos:
                                        if campo.get("field") == "product" and campo.get("status") == "ok":
                                            ean_img_url = produtos_eandata[0].get("img_url", "")
                            except Exception as e:
                                logger.warning(f"Erro ao extrair imagem da EANdata: {str(e)}")

                            # Verifica se imagem da EANdata é válida
                            if ean_img_url and not ean_img_url.lower().startswith("image error"):
                                extras["urlImagem"] = ean_img_url
                            elif "thumbnail" in dict_retorno and dict_retorno["thumbnail"]:
                                extras["urlImagem"] = dict_retorno["thumbnail"]

                            if extras:
                                resposta["produto"]["infoAdicional"] = extras
            else:
                resposta["status"] = "error"
                resposta["cStat"] = ret_cons_gtin.get("cStat", "999")
                resposta["xMotivo"] = ret_cons_gtin.get("xMotivo", "Erro na consulta SEFAZ")
                resposta["produto"] = None
                logger.warning(f"Erro SEFAZ: cStat={resposta['cStat']}, xMotivo={resposta['xMotivo']}")
        return resposta

    except Exception as e:
        logger.error(f"Erro ao formatar resposta personalizada: {str(e)}")
        return {
            "status": "error",
            "cStat": "999",
            "xMotivo": f"Erro ao formatar resposta: {str(e)}",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "produto": None
        }

# =========================
# Gerenciamento de Tokens para Bluesoft Cosmos
# =========================
class TokenManager:
    def __init__(self):
        self.tokens = []
        self.current_index = 0
        self.usage_count = {}
        self.last_reset_date = datetime.now().date()
        self.load_tokens()

    def load_tokens(self):
        main_token = settings.cosmos_api_token
        if main_token:
            self.tokens.append(main_token)
            self.usage_count[main_token] = 0
        i = 1
        while True:
            token = os.getenv(f"COSMOS_API_TOKEN_{i}")
            if not token:
                break
            self.tokens.append(token)
            self.usage_count[token] = 0
            i += 1
        logger.info(f"Carregados {len(self.tokens)} tokens para a API Bluesoft Cosmos")

    def get_token(self):
        today = datetime.now().date()
        if today > self.last_reset_date:
            self.reset_usage_counts()
            self.last_reset_date = today
        if not self.tokens:
            return None
        for _ in range(len(self.tokens)):
            token = self.tokens[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.tokens)
            if self.usage_count[token] < 25:
                return token
        logger.warning("Todos os tokens da API Bluesoft Cosmos atingiram o limite diário")
        return None

    def increment_usage(self, token):
        if token in self.usage_count:
            self.usage_count[token] += 1
            logger.info(f"Token Bluesoft: {token[:8]}... - Uso: {self.usage_count[token]}/25")

    def reset_usage_counts(self):
        for token in self.tokens:
            self.usage_count[token] = 0
        logger.info("Contadores de uso dos tokens Bluesoft resetados (novo dia)")

token_manager = TokenManager()

# =========================
# Consulta à API Bluesoft Cosmos (assíncrono)
# =========================
async def consultar_bluesoft_cosmos(codigo_gtin: str) -> dict:
    gtin_seguro = re.sub(r'[^\d]', '', codigo_gtin)
    token = token_manager.get_token()
    if not token:
        logger.warning("Token da API Bluesoft Cosmos não disponível")
        return None
    url = f"https://api.cosmos.bluesoft.com.br/gtins/{gtin_seguro}"
    headers = {
        "X-Cosmos-Token": token,
        "User-Agent": "Cosmos-API-Request"
    }
    max_retries = 3
    retry_count = 0
    async with httpx.AsyncClient(timeout=30) as client:
        while retry_count < max_retries:
            try:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    token_manager.increment_usage(token)
                    return response.json()
                elif response.status_code == 404:
                    token_manager.increment_usage(token)
                    logger.info(f"Produto não encontrado na API Bluesoft Cosmos: {codigo_gtin}")
                    return None
                elif response.status_code == 429:
                    logger.warning("Limite de requisições atingido para o token atual. Tentando outro token.")
                    current_token = token
                    self_token = current_token  # Guarda o token atual
                    token_manager.usage_count[self_token] = 25
                    token = token_manager.get_token()
                    if not token:
                        logger.warning("Todos os tokens atingiram o limite diário")
                        return None
                    headers["X-Cosmos-Token"] = token
                    continue
                else:
                    response.raise_for_status()
            except (httpx.TimeoutException, httpx.ConnectionError) as e:
                retry_count += 1
                if retry_count < max_retries:
                    logger.warning(f"Erro de conexão na API Bluesoft. Tentativa {retry_count}/{max_retries}: {str(e)}")
                    await asyncio.sleep(2 ** retry_count)
                else:
                    logger.error(f"Falha após {max_retries} tentativas: {str(e)}")
                    return None
            except Exception as e:
                logger.error(f"Erro ao consultar API Bluesoft Cosmos: {str(e)}")
                return None
            break
    return None

def formatar_resposta_bluesoft(dados_bluesoft: dict, codigo_gtin: str) -> dict:
    try:
        if not dados_bluesoft:
            return None

        nome_produto = dados_bluesoft.get("description", "")

        resposta = {
            "status": "success",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cStat": "100",
            "xMotivo": "Consulta realizada com sucesso",
            "produto": {
                "GTIN": codigo_gtin,
                "tpGTIN": f"GTIN-{len(codigo_gtin)}",
                "xProd": dados_bluesoft.get("description", "").upper(),
                "NCM": dados_bluesoft.get("ncm", {}).get("code", "") if "ncm" in dados_bluesoft else "",
                "CEST": dados_bluesoft.get("cest", {}).get("code", "") if "cest" in dados_bluesoft else "",
                "fonte": "Bluesoft Cosmos"
            }
        }

        info_adicional = {}
        if "brand" in dados_bluesoft and dados_bluesoft["brand"]:
            info_adicional["xMarca"] = dados_bluesoft["brand"].get("name", "")
        if "gpc" in dados_bluesoft and dados_bluesoft["gpc"]:
            info_adicional["xCategoria"] = dados_bluesoft["gpc"].get("description", "")
        if "thumbnail" in dados_bluesoft and dados_bluesoft["thumbnail"]:
            info_adicional["urlImagem"] = dados_bluesoft["thumbnail"]
        if "commercial_unit" in dados_bluesoft and dados_bluesoft["commercial_unit"]:
            info_adicional["unidComercial"] = dados_bluesoft["commercial_unit"].get("type_abbreviation", "")
        if "width" in dados_bluesoft and "height" in dados_bluesoft and "length" in dados_bluesoft:
            info_adicional["dimensoes"] = {
                "largura": dados_bluesoft.get("width", 0),
                "altura": dados_bluesoft.get("height", 0),
                "comprimento": dados_bluesoft.get("length", 0),
                "unidade": "mm"
            }
        if "net_weight" in dados_bluesoft:
            info_adicional["pesoLiquido"] = dados_bluesoft.get("net_weight", 0)
        if "gross_weight" in dados_bluesoft:
            info_adicional["pesoBruto"] = dados_bluesoft.get("gross_weight", 0)
        if info_adicional:
            resposta["produto"]["infoAdicional"] = info_adicional
        return resposta
    except Exception as e:
        logger.error(f"Erro ao formatar resposta da Bluesoft: {str(e)}")
        return None

# ===========================================================================
# Extrai o peso ou volume de um produto a partir de uma string de descrição.
# ===========================================================================
def extrair_peso_unidade(descricao: str) -> dict:
    """
    Extrai o peso de um produto a partir de sua descrição e retorna a unidade padronizada,
    o valor numérico e a descrição limpa (sem o trecho do peso).

    A função utiliza expressões regulares para identificar padrões como "1kg", "500 g", "2,5 libras", etc.,
    e converte a unidade encontrada para um nome padronizado em inglês.

    Args:
        descricao (str): A descrição textual do produto contendo ou não uma indicação de peso.

    Returns:
        dict: Um dicionário com as seguintes chaves:
            - "valor" (float ou None): O valor numérico do peso identificado (ex: 2.5).
            - "unidade" (str ou None): A unidade padronizada (ex: 'kilograms', 'grams', etc.).
            - "descricao" (str): A descrição original com o peso removido, se identificado.
    """
    # Dicionário de mapeamento de diferentes formas de escrita de unidades para nomes padronizados
    unidades = {
        "mg": "milligrams", "miligrama": "milligrams", "miligramas": "milligrams",
        "g": "grams", "grama": "grams", "gramas": "grams",
        "kg": "kilograms", "quilograma": "kilograms", "quilogramas": "kilograms",
        "t": "tons", "tonelada": "tons", "toneladas": "tons",
        "lb": "pounds", "lbs": "pounds", "libra": "pounds", "libras": "pounds",
        "oz": "ounces", "onça": "ounces", "onças": "ounces",
        "dwt": "pennyweight", "pennyweight": "pennyweight"
    }

    # Expressão regular para capturar número com vírgula ou ponto seguido de unidade
    padrao = re.compile(
        r"(\d+(?:[.,]\d+)?)\s*"  # valor numérico com separador decimal opcional
        r"(mg|g|kg|t|lb|lbs|oz|dwt|"  # unidades abreviadas
        r"miligrama[s]?|grama[s]?|quilograma[s]?|tonelada[s]?|libra[s]?|onça[s]?|pennyweight)",
        re.IGNORECASE
    )

    # Procura o primeiro trecho da descrição que combine com o padrão
    match = padrao.search(descricao.lower())

    if match:
        # Se encontrou, separa valor e unidade
        valor, unidade_bruta = match.groups()
        unidade_normalizada = unidades.get(unidade_bruta.lower())

        if unidade_normalizada:
            # Remove o trecho correspondente da descrição original
            trecho = match.group(0)
            descricao_limpa = re.sub(re.escape(trecho), '', descricao, flags=re.IGNORECASE).strip()

            # Remove espaços duplicados
            descricao_limpa = re.sub(r'\s{2,}', ' ', descricao_limpa)

            return {
                "valor": float(valor.replace(",", ".")),  # Normaliza separador decimal
                "unidade": unidade_normalizada,
                "descricao": descricao_limpa
            }

    # Caso nenhum peso seja identificado, retorna valores nulos e a descrição original
    return {
        "valor": None,
        "unidade": None,
        "descricao": descricao
    }

# =========================
# FastAPI e Endpoints
# =========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Inicializando API de consulta GTIN")
    limpar_logs_antigos(30)
    yield
    logger.info("Encerrando API de consulta GTIN")

app = FastAPI(
    title="API de Consulta GTIN",
    description="""
    API para consulta de produtos via GTIN/EAN na base da SEFAZ com fallback para Bluesoft Cosmos.
    
    Esta API permite consultar informações detalhadas de produtos a partir do seu código GTIN/EAN,
    utilizando o webservice oficial da SEFAZ e enriquecendo os dados com informações adicionais.
    
    Características principais:
    - Consulta na base oficial da SEFAZ
    - Fallback para Bluesoft Cosmos quando não encontrado na SEFAZ
    - Enriquecimento de dados com EANdata
    - Cache inteligente para melhorar performance
    - Validação de códigos GTIN
    """,
    version="1.0.0",
    lifespan=lifespan,
    contact={
        "name": settings.contato_nome,
        "email": settings.contato_email,
        "empresa": settings.empresa_nome,
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    openapi_tags=[
        {
            "name": "Consultas",
            "description": "Endpoints para consulta de produtos por GTIN/EAN"
        },
        {
            "name": "Monitoramento",
            "description": "Endpoints para monitoramento e verificação de saúde da API"
        },
        {
            "name": "Documentação",
            "description": "Endpoints com informações e exemplos de uso da API"
        }
    ],
    docs_url="/",
    redoc_url="/redoc",
)

@app.get("/", 
    tags=["Documentação"],
    summary="Informações sobre a API",
    description="Retorna informações básicas sobre a API e links para documentação",
    response_description="Informações básicas da API e links úteis"
)
async def root():
    """
    Endpoint raiz que fornece informações básicas sobre a API.
    
    Retorna:
        dict: Informações sobre a API, versão, links para documentação e endpoints disponíveis
    """
    return {
        "api": "API de Consulta GTIN",
        "versao": "1.0.0",
        "descricao": "API para consulta de produtos por código GTIN/EAN",
        "documentacao": "/docs",
        "redoc": "/redoc",
        "endpoints": {
            "consulta_gtin": "/gtin/{codigo_gtin}",
            "verificacao_saude": "/health"
        },
        "empresa": settings.empresa_nome,
        "contato": settings.contato_email
    }

@app.get("/gtin/{codigo_gtin}", 
    tags=["Consultas"],
    summary="Consultar produto por GTIN/EAN",
    description="""
    Consulta informações detalhadas de um produto pelo seu código GTIN/EAN.
    
    A consulta é realizada primeiro na base da SEFAZ e, caso não encontre o produto,
    realiza uma consulta na base Bluesoft Cosmos como fallback.
    
    Os dados são enriquecidos com informações adicionais quando disponíveis.
    """,
    response_description="Informações detalhadas do produto",
    responses={
        200: {
            "description": "Produto encontrado com sucesso",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "provider": "PAIRUS Soluções Tecnológicas",
                        "timestamp": "2023-05-15 10:30:45",
                        "cStat": "100",
                        "xMotivo": "Consulta realizada com sucesso",
                        "produto": {
                            "GTIN": "7891000315507",
                            "tpGTIN": "GTIN-13",
                            "xProd": "LEITE CONDENSADO MOÇA NESTLÉ 395G",
                            "NCM": "04029900",
                            "CEST": "1702100",
                            "fonte": "SEFAZ"
                        }
                    }
                }
            }
        },
        400: {
            "description": "Código GTIN inválido",
            "content": {
                "application/json": {
                    "example": {
                        "status": "error",
                        "provider": "PAIRUS Soluções Tecnológicas",
                        "timestamp": "2023-05-15 10:31:22",
                        "cStat": "225",
                        "xMotivo": "Código GTIN inválido. Verifique se o formato e dígito verificador estão corretos.",
                        "produto": None
                    }
                }
            }
        },
        404: {
            "description": "Produto não encontrado",
            "content": {
                "application/json": {
                    "example": {
                        "status": "error",
                        "provider": "PAIRUS Soluções Tecnológicas",
                        "timestamp": "2023-05-15 10:31:22",
                        "cStat": "226",
                        "xMotivo": "Produto não encontrado nas bases consultadas.",
                        "produto": None
                    }
                }
            }
        },
        500: {
            "description": "Erro interno do servidor",
            "content": {
                "application/json": {
                    "example": {
                        "status": "error",
                        "provider": "PAIRUS Soluções Tecnológicas",
                        "timestamp": "2023-05-15 10:31:22",
                        "cStat": "999",
                        "xMotivo": "Erro interno do servidor.",
                        "produto": None
                    }
                }
            }
        }
    }
)
async def consultar_gtin(codigo_gtin: str, timestamp: int = Depends(lambda: int(time.time()) // 3600)):
    """
    Consulta informações de um produto pelo código GTIN/EAN.
    
    Args:
        codigo_gtin (str): Código GTIN/EAN do produto (8, 12, 13 ou 14 dígitos)
        timestamp (int): Timestamp para invalidação do cache (gerado automaticamente)
        
    Returns:
        dict: Informações detalhadas do produto ou mensagem de erro
    """
    logger.info("--------------------------------------------------")
    logger.info(f"Iniciando consulta para GTIN: {codigo_gtin}")

    # Validação do código GTIN
    if not validate_gtin(codigo_gtin):
        return {
            "status": "error",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cStat": "225",
            "xMotivo": "Código GTIN inválido. Verifique se o formato e dígito verificador estão corretos.",
            "produto": None,
        }

    # Verificação do certificado digital
    pfx_file = settings.certificado_caminho
    pfx_password = settings.certificado_senha
    if not pfx_file or not pfx_password:
        logger.error("Configurações do certificado não encontradas")
        return {
            "status": "error",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cStat": "280",
            "xMotivo": "Erro de configuração do servidor. Contate o administrador.",
            "produto": None,
        }
    if not os.path.isfile(pfx_file):
        logger.error(f"Arquivo de certificado não encontrado: {pfx_file}")
        return {
            "status": "error",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cStat": "281",
            "xMotivo": "Certificado digital não encontrado. Contate o administrador.",
            "produto": None,
        }

    # Consulta ao webservice da SEFAZ
    try:
        loop = asyncio.get_event_loop()
        xml_retorno = await loop.run_in_executor(None, consultar_gtin_pfx_cached, codigo_gtin, pfx_file, pfx_password)
    except Exception as e:
        logger.error(f"Falha na consulta ao webservice SEFAZ: {str(e)}")
        return {
            "status": "error",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cStat": "108",
            "xMotivo": "Serviço SEFAZ temporariamente indisponível. Tente novamente mais tarde.",
            "produto": None,
        }

    # Processamento da resposta
    try:
        dict_retorno = xmltodict.parse(xml_retorno)
        resposta_formatada = formatar_resposta_personalizada(dict_retorno, codigo_gtin)
        
        # Se não encontrou na SEFAZ, tenta na Bluesoft Cosmos
        if resposta_formatada.get("status") == "error" or not resposta_formatada.get("produto"):
            logger.info(f"Produto não encontrado na SEFAZ, tentando Bluesoft Cosmos: {codigo_gtin}")
            dados_bluesoft = await consultar_bluesoft_cosmos(codigo_gtin)
            if dados_bluesoft:
                resposta_bluesoft = formatar_resposta_bluesoft(dados_bluesoft, codigo_gtin)
                if resposta_bluesoft:
                    logger.info(f"Produto encontrado na Bluesoft Cosmos: {codigo_gtin}")
                    resposta_bluesoft = await enriquecer_com_eandata(resposta_bluesoft)
                    logger.info(f"Dados do produto enviado para o EANData.com: {codigo_gtin}")
                    logger.info("--------------------------------------------------")
                    return resposta_bluesoft
            
            # Se não encontrou em nenhuma base
            if resposta_formatada.get("status") == "error":
                return resposta_formatada
            else:
                return {
                    "status": "error",
                    "provider": "PAIRUS Soluções Tecnológicas",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "cStat": "226",
                    "xMotivo": "Produto não encontrado nas bases consultadas.",
                    "produto": None,
                }
        resposta_formatada = await enriquecer_com_eandata(resposta_formatada)
        logger.info("--------------------------------------------------")
        return resposta_formatada
    except Exception as xml_error:
        logger.error(f"Erro ao processar XML: {str(xml_error)}")
        logger.info(f"Erro no processamento SEFAZ, tentando Bluesoft Cosmos: {codigo_gtin}")
        
        # Tenta na Bluesoft Cosmos em caso de erro no processamento
        dados_bluesoft = await consultar_bluesoft_cosmos(codigo_gtin)
        if dados_bluesoft:
            resposta_bluesoft = formatar_resposta_bluesoft(dados_bluesoft, codigo_gtin)
            if resposta_bluesoft:
                return resposta_bluesoft
        # Se não encontrou em nenhuma base
        logger.info("--------------------------------------------------")
        return {
            "status": "error",
            "cStat": "215",
            "xMotivo": "Erro ao processar resposta do serviço SEFAZ",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "produto": None,
        }

@app.get("/health", 
    tags=["Monitoramento"],
    summary="Verificação de saúde da API",
    description="Verifica se a API está funcionando corretamente",
    response_description="Status da API",
    responses={
        200: {
            "description": "API funcionando normalmente",
            "content": {
                "application/json": {
                    "example": {
                        "status": "ok",
                        "timestamp": "2023-05-15 10:30:45"
                    }
                }
            }
        }
    }
)
async def health_check():
    """
    Endpoint para verificação de saúde da API.
    
    Utilizado para monitoramento e verificação de disponibilidade do serviço.
    
    Returns:
        dict: Status da API e timestamp atual
    """
    return {
        "status": "ok",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# Adicionando um novo endpoint para exemplos de uso
@app.get("/exemplos", 
    tags=["Documentação"],
    summary="Exemplos de uso da API",
    description="Fornece exemplos práticos de como utilizar a API",
    response_description="Exemplos de requisições e respostas"
)
async def exemplos_uso():
    """
    Endpoint com exemplos de uso da API.
    
    Fornece exemplos práticos de como utilizar a API, incluindo exemplos
    de requisições e respostas para facilitar a integração por desenvolvedores.
    
    Returns:
        dict: Exemplos de uso da API
    """
    return {
        "exemplos": [
            {
                "descricao": "Consulta de produto por GTIN",
                "endpoint": "/gtin/7891000315507",
                "metodo": "GET",
                "resposta_exemplo": {
                    "status": "success",
                    "provider": "PAIRUS Soluções Tecnológicas",
                    "timestamp": "2023-05-15 10:30:45",
                    "cStat": "100",
                    "xMotivo": "Consulta realizada com sucesso",
                    "produto": {
                        "GTIN": "7891000315507",
                        "tpGTIN": "GTIN-13",
                        "xProd": "LEITE CONDENSADO MOÇA NESTLÉ 395G",
                        "NCM": "04029900",
                        "CEST": "1702100",
                        "fonte": "SEFAZ"
                    }
                }
            },
            {
                "descricao": "Consulta de produto inexistente",
                "endpoint": "/gtin/7891000000000",
                "metodo": "GET",
                "resposta_exemplo": {
                    "status": "error",
                    "provider": "PAIRUS Soluções Tecnológicas",
                    "timestamp": "2023-05-15 10:31:22",
                    "cStat": "226",
                    "xMotivo": "Produto não encontrado nas bases consultadas.",
                    "produto": None
                }
            }
        ],
        "notas": [
            "Os códigos GTIN devem ser válidos (8, 12, 13 ou 14 dígitos)",
            "A API consulta primeiro a base da SEFAZ e, se não encontrar, consulta a base Bluesoft Cosmos",
            "O campo 'fonte' na resposta indica a origem dos dados (SEFAZ ou Bluesoft Cosmos)"
        ]
    }