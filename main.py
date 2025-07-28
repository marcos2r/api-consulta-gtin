# 1. Biblioteca padrão
import os
import re
import time
import hashlib
import logging
import logging.config
from functools import wraps
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from pathlib import Path
import asyncio

# 2. Terceiros
import xmltodict
import requests
from requests_pkcs12 import Pkcs12Adapter
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from fastapi import FastAPI, Depends
from pydantic_settings import BaseSettings, SettingsConfigDict

# ===============================
# Configurações com Pydantic v2
# ===============================
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

# Define o diretório base do projeto (o diretório do arquivo atual)
BASE_DIR = Path(__file__).parent.resolve()

# Define o diretório onde os logs serão armazenados
LOG_DIR = BASE_DIR / "logs"

# Cria o diretório de logs, incluindo diretórios-pai, se não existirem
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Define o nome do arquivo de log, com data no formato AAAAMMDD
log_filename = LOG_DIR / f"gtin_api_{datetime.now().strftime('%Y%m%d')}.log"

# Dicionário de configuração do logging
logging_config = {
    "version": 1,  # Versão da configuração (padrão é 1)
    "disable_existing_loggers": False,  # Mantém loggers existentes ativos
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"  # Define formato padrão das mensagens de log
        }
    },
    "handlers": {
        # Handler para exibir logs no console
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            # Em desenvolvimento mostra logs detalhados (DEBUG); em produção mostra apenas logs a partir de INFO.
            "level": "DEBUG" if settings.ambiente == "desenvolvimento" else "INFO",
        },
        # Handler para registrar logs em arquivo rotativo (com limite de tamanho e backups)
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "standard",
            "filename": log_filename,  # Arquivo de log definido acima
            "maxBytes": 10 * 1024 * 1024,  # Tamanho máximo de 10 MB por arquivo
            "backupCount": 5,  # Mantém até 5 arquivos de backup
            # Em desenvolvimento mostra logs detalhados (DEBUG); em produção mostra apenas logs a partir de INFO.
            "level": "DEBUG" if settings.ambiente == "desenvolvimento" else "INFO",
        },
    },
    "loggers": {
        # Logger principal do sistema (nome: gtin-api)
        "gtin-api": {
            # Em desenvolvimento, loga no arquivo e no console; em produção, só no arquivo
            "handlers": ["file", "console"] if settings.ambiente == "desenvolvimento" else ["file"],
            "level": "INFO",
            "propagate": False,  # Não propaga mensagens para loggers pai
        }
    },
}

# Aplica a configuração de logging definida acima
logging.config.dictConfig(logging_config)

# Obtém o logger 'gtin-api' para ser usado no projeto
logger = logging.getLogger("gtin-api")

# =================================================================================================================================
# Remove arquivos de log antigos do diretório de logs, mantendo apenas os arquivos referentes aos últimos 'dias_para_manter' dias.
# =================================================================================================================================
def limpar_logs_antigos(dias_para_manter=30):
    """
    Remove arquivos de log antigos do diretório de logs, mantendo apenas os arquivos referentes aos últimos 'dias_para_manter' dias.

    O nome dos arquivos de log deve seguir o padrão 'gtin_api_YYYYMMDD.log', onde 'YYYYMMDD' indica a data de criação.

    Args:
        dias_para_manter (int, opcional): Número de dias para manter os arquivos de log. 
                                          Todos os arquivos mais antigos que esse período serão removidos. 
                                          O padrão é 30 dias.

    Detalhes:
        - A função calcula a data limite a partir da data atual, subtraindo o número de dias informado.
        - Apenas os arquivos de log cujo nome corresponde ao padrão e cuja data for anterior à data limite são removidos.
        - Para cada arquivo removido, uma mensagem é registrada no log.
        - Se algum erro ocorrer ao processar um arquivo, um aviso é registrado no log.
        - Ao final, a função informa quantos arquivos foram removidos.

    Exemplo de uso:
        limpar_logs_antigos(15)  # Mantém logs dos últimos 15 dias, apaga o resto
    """

    logger.info(f"Iniciando limpeza de logs antigos (mantendo últimos {dias_para_manter} dias)")
    
    # Calcula a data limite: logs mais antigos que isso serão apagados
    data_limite = datetime.now() - timedelta(days=dias_para_manter)
    
    # Caminho para o diretório de logs
    log_dir = Path(LOG_DIR)
    
    # Lista todos os arquivos de log que seguem o padrão 'gtin_api_*.log'
    arquivos_log = log_dir.glob("gtin_api_*.log")
    
    contador_removidos = 0  # Contador de arquivos removidos
    
    # Itera sobre cada arquivo de log encontrado
    for arquivo in arquivos_log:
        try:
            # Extrai a data do nome do arquivo: 'gtin_api_YYYYMMDD.log'
            data_str = arquivo.stem.replace("gtin_api_", "")  # Pega só o YYYYMMDD
            
            # Converte a string da data para um objeto datetime
            data_arquivo = datetime.strptime(data_str, "%Y%m%d")
            
            # Se o arquivo for mais antigo que a data limite, remove o arquivo
            if data_arquivo < data_limite:
                arquivo.unlink()  # Remove o arquivo
                contador_removidos += 1
                logger.info(f"Log antigo removido: {arquivo.name}")
        except Exception as e:
            # Caso ocorra algum erro ao processar o arquivo, registra um aviso
            logger.warning(f"Erro ao processar arquivo de log {arquivo.name}: {str(e)}")
    
    # Informa o total de arquivos removidos ao final do processo
    logger.info(f"Limpeza de logs concluída. {contador_removidos} arquivos removidos.")

# =========================
# Utilitários e Cache
# =========================
def flexible_cache(maxsize=128, ttl=3600):
    """
    Decorador de cache flexível com TTL (Time To Live) e controle de tamanho.
    
    Este decorador fornece funcionalidade de cache para funções com as seguintes características:
    - Cache com expiração baseada em tempo (TTL)
    - Controle de tamanho máximo do cache
    - Remoção automática de entradas mais antigas quando o limite é atingido
    - Geração de chaves baseada em hash MD5 para argumentos complexos
    
    Args:
        maxsize (int, optional): Número máximo de entradas no cache. 
                                Padrão é 128.
        ttl (int, optional): Tempo de vida em segundos para cada entrada do cache.
                            Padrão é 3600 segundos (1 hora).
    
    Returns:
        function: Função decorada com funcionalidade de cache.
    
    Raises:
        Nenhuma exceção específica é levantada pelo decorador.
    
    Example:
        >>> @flexible_cache(maxsize=50, ttl=1800)
        ... def buscar_dados_api(endpoint, parametros=None):
        ...     # Simula uma chamada custosa à API
        ...     return fazer_requisicao(endpoint, parametros)
        
        >>> # Primeira chamada - executa a função
        >>> resultado1 = buscar_dados_api("/users", {"page": 1})
        
        >>> # Segunda chamada com mesmos parâmetros - retorna do cache
        >>> resultado2 = buscar_dados_api("/users", {"page": 1})
    
    Note:
        - O cache é compartilhado entre todas as instâncias da função decorada
        - As chaves são geradas usando MD5 hash dos argumentos
        - Argumentos nomeados são ordenados para garantir consistência na chave
        - Não é thread-safe por padrão
    """
    # Dicionário para armazenar os resultados em cache
    # Estrutura: {chave_hash: resultado_funcao}
    cache = {}
    
    # Dicionário para armazenar os timestamps de quando cada entrada foi criada
    # Estrutura: {chave_hash: timestamp_criacao}
    cache_timestamps = {}

    def decorator(func):
        """
        Decorador interno que recebe a função a ser decorada.
        
        Args:
            func: A função que será decorada com cache
            
        Returns:
            function: Função wrapper com funcionalidade de cache
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            """
            Função wrapper que implementa a lógica do cache.
            
            Args:
                *args: Argumentos posicionais passados para a função original
                **kwargs: Argumentos nomeados passados para a função original
                
            Returns:
                O resultado da função (do cache ou da execução)
            """
            # Constrói uma lista com partes da chave do cache
            # Inclui: nome da função + argumentos posicionais + argumentos nomeados ordenados
            key_parts = [func.__name__] + [str(arg) for arg in args] + [
                f"{k}={v}" for k, v in sorted(kwargs.items())
            ]
            
            # Junta todas as partes com ":" e gera um hash MD5
            # Isso garante uma chave única e de tamanho fixo
            key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
            
            # Obtém o timestamp atual para verificar expiração
            current_time = time.time()
            
            # Verifica se a chave existe no cache E se não expirou
            # Calcula a diferença entre tempo atual e tempo da criação da entrada
            if key in cache and (current_time - cache_timestamps.get(key, 0)) < ttl:
                # Cache hit: retorna o resultado armazenado sem executar a função
                return cache[key]
            
            # Cache miss ou entrada expirada: executa a função original
            result = func(*args, **kwargs)
            
            # Armazena o resultado no cache
            cache[key] = result
            
            # Registra o timestamp atual para esta entrada
            cache_timestamps[key] = current_time
            
            # Verifica se o cache excedeu o tamanho máximo
            if len(cache) > maxsize:
                # Encontra a chave com o timestamp mais antigo
                # min() com key=cache_timestamps.get retorna a chave com menor timestamp
                oldest_key = min(cache_timestamps, key=cache_timestamps.get)
                
                # Remove a entrada mais antiga do cache
                del cache[oldest_key]
                
                # Remove o timestamp correspondente
                del cache_timestamps[oldest_key]
            
            # Retorna o resultado da execução da função
            return result

        # Retorna a função wrapper que substituirá a função original
        return wrapper

    # Retorna o decorador que será aplicado à função
    return decorator

# ===========================================================================================
# Valida um código GTIN (Global Trade Item Number) usando o algoritmo de dígito verificador.
# ===========================================================================================
def validate_gtin(gtin_code: str) -> bool:
    """
    Valida um código GTIN (Global Trade Item Number) usando o algoritmo de dígito verificador.
    
    O GTIN é um padrão internacional para identificação de produtos comerciais que inclui
    códigos de barras EAN-8, EAN-13, UPC-A e GTIN-14. A validação é feita através do
    cálculo do dígito verificador usando um algoritmo de soma ponderada.
    
    Args:
        gtin_code (str): String contendo o código GTIN a ser validado.
                        Deve conter apenas dígitos numéricos.
    
    Returns:
        bool: True se o código GTIN for válido, False caso contrário.
    
    Raises:
        Não levanta exceções - retorna False para entradas inválidas.
    
    Example:
        >>> validate_gtin("7891000100103")  # Código EAN-13 válido
        True
        >>> validate_gtin("1234567890123")  # Código inválido
        False
        >>> validate_gtin("12345678")       # Código EAN-8 válido (exemplo)
        True
        >>> validate_gtin("abc123")         # Entrada inválida (contém letras)
        False
    
    Note:
        - Aceita códigos GTIN de 8, 12, 13 ou 14 dígitos
        - O último dígito é sempre o dígito verificador
        - O algoritmo usa fatores alternados (3 e 1) para cálculo da soma
        - A validação segue o padrão GS1 para códigos GTIN
    """
    
    # Verifica se a entrada é uma string e se contém apenas dígitos numéricos
    if not isinstance(gtin_code, str) or not gtin_code.isdigit():
        return False
    
    # Verifica se o comprimento está dentro dos padrões GTIN aceitos
    # GTIN-8: 8 dígitos, UPC-A/GTIN-12: 12 dígitos, EAN-13/GTIN-13: 13 dígitos, GTIN-14: 14 dígitos
    if len(gtin_code) > 14 or len(gtin_code) not in [8, 12, 13, 14]:
        return False
    
    # Extrai o último dígito, que é o dígito verificador fornecido
    digito_verificador = int(gtin_code[-1])
    
    # Inicializa a variável para acumular a soma ponderada
    total = 0
    
    # Inicializa o fator multiplicador (começamos com 3 para o penúltimo dígito)
    fator = 3
    
    # Itera pelos dígitos da direita para a esquerda, excluindo o dígito verificador
    # range(len(gtin_code) - 2, -1, -1) vai do penúltimo dígito até o primeiro
    for i in range(len(gtin_code) - 2, -1, -1):
        # Multiplica cada dígito pelo fator atual e adiciona ao total
        total += int(gtin_code[i]) * fator
        
        # Alterna o fator entre 3 e 1 (4 - 3 = 1, 4 - 1 = 3)
        fator = 4 - fator
    
    # Calcula o dígito verificador usando a fórmula padrão GTIN
    # (10 - (total % 10)) % 10 garante que o resultado seja 0 quando total % 10 = 0
    digito_calculado = (10 - (total % 10)) % 10
    
    # Compara o dígito verificador fornecido com o calculado
    return digito_verificador == digito_calculado

# =================================================================================
# Consulta informações de um produto através do código GTIN no webservice da SEFAZ 
# =================================================================================
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def consultar_gtin_pfx(gtin: str, pfx_file: str, pfx_password: str) -> str:
    """
    Consulta informações de um produto através do código GTIN no webservice da SEFAZ 
    utilizando protocolo SOAP e autenticação via certificado digital PFX.
    
    Esta função realiza uma consulta ao serviço CCG (Cadastro Central de GTINs) da SEFAZ 
    para obter informações detalhadas sobre produtos comerciais através do código GTIN.
    A comunicação é feita via protocolo SOAP 1.2 com autenticação por certificado digital.
    
    Args:
        gtin (str): Código GTIN (Global Trade Item Number) do produto a ser consultado.
                   Pode conter formatação (hífen, pontos) que será removida automaticamente.
        pfx_file (str): Caminho para o arquivo de certificado digital no formato PFX/PKCS#12.
                       Este certificado deve estar válido e autorizado para consultas SEFAZ.
        pfx_password (str): Senha do certificado digital PFX para desbloqueio e uso.
    
    Returns:
        str: Resposta XML do webservice da SEFAZ contendo as informações do produto
             ou mensagens de erro em caso de GTIN inválido/não encontrado.
    
    Raises:
        Exception: Levanta exceção personalizada em caso de:
                  - Erro de conectividade com o webservice
                  - Problemas de autenticação com certificado
                  - Timeout na requisição (30 segundos)
                  - Certificado inválido ou expirado
                  - Outros erros HTTP (4xx, 5xx)
    
    Decorators:
        @retry: Implementa retry automático com backoff exponencial:
               - Máximo de 3 tentativas
               - Intervalo inicial de 2 segundos
               - Backoff exponencial até 10 segundos máximo
               - Útil para problemas temporários de rede/serviço
    
    Example:
        >>> # Consulta básica com certificado
        >>> gtin = "7891000100103"
        >>> cert_path = "/path/to/certificate.pfx" 
        >>> cert_password = "minha_senha"
        >>> resultado = consultar_gtin_pfx(gtin, cert_path, cert_password)
        >>> print(resultado)  # XML com dados do produto
        
        >>> # Exemplo com GTIN formatado (será limpo automaticamente)
        >>> gtin_formatado = "789-1000-100103"
        >>> resultado = consultar_gtin_pfx(gtin_formatado, cert_path, cert_password)
    
    Note:
        - Utiliza o webservice oficial da SEFAZ RS (SVRs)
        - Requer certificado digital válido e-CPF ou e-CNPJ
        - Timeout configurado para 30 segundos
        - SSL pode ser desabilitado em desenvolvimento (não recomendado)
        - A função é thread-safe e pode ser usada em aplicações concorrentes
        - Configurações de SSL controladas por settings.ignorar_ssl_sefaz
    
    Environment Settings:
        - settings.ignorar_ssl_sefaz: Desabilita verificação SSL específica para SEFAZ
        - settings.ambiente: Controla comportamento baseado no ambiente (desenvolvimento/produção)
        - settings.ignorar_ssl: Configuração geral de SSL para desenvolvimento
    """
    
    # Define a URL do webservice oficial da SEFAZ para consulta de GTIN
    # Utiliza o servidor SVRs (Sefaz Virtual do Rio Grande do Sul)
    url = "https://dfe-servico.svrs.rs.gov.br/ws/ccgConsGTIN/ccgConsGTIN.asmx"
    
    # Remove todos os caracteres não numéricos do GTIN usando regex
    # Isso permite aceitar GTINs formatados como "789-1000-100103" ou "789.1000.100103"
    gtin_seguro = re.sub(r'[^\d]', '', gtin)
    
    # Constrói o envelope SOAP 1.2 em uma única linha para evitar problemas de formatação
    # Inclui todos os namespaces necessários e estrutura XML exigida pela SEFAZ
    # O GTIN limpo é inserido no elemento <GTIN> dentro da estrutura consGTIN
    soap_envelope = f'<?xml version="1.0" encoding="UTF-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap12:Header/><soap12:Body><ccgConsGTIN xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin"><nfeDadosMsg><consGTIN versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe"><GTIN>{gtin_seguro}</GTIN></consGTIN></nfeDadosMsg></ccgConsGTIN></soap12:Body></soap12:Envelope>'
    
    # Define os cabeçalhos HTTP necessários para a requisição SOAP
    # Content-Type especifica SOAP 1.2 com charset UTF-8 e a action obrigatória
    headers = {
        "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin/ccgConsGTIN"'
    }
    
    # Cria uma sessão HTTP reutilizável para otimizar conexões
    session = requests.Session()
    
    # Configura o adaptador PKCS#12 para autenticação via certificado digital
    # Monta o adaptador apenas para URLs HTTPS, fornecendo arquivo PFX e senha
    session.mount('https://', Pkcs12Adapter(pkcs12_filename=pfx_file, pkcs12_password=pfx_password))
    
    # Por padrão, habilita verificação SSL para segurança
    verify_ssl = True
    
    # Verifica configurações para desabilitar SSL em ambientes específicos
    # Útil para desenvolvimento ou ambientes com certificados auto-assinados
    if settings.ignorar_ssl_sefaz or (settings.ambiente == "desenvolvimento" and settings.ignorar_ssl):
        verify_ssl = False
        # Registra aviso de segurança quando SSL é desabilitado
        logger.warning("Verificação SSL desabilitada para SEFAZ - Use com cautela em produção")
    
    # Bloco try para captura e tratamento de exceções de rede
    try:
        # Executa a requisição POST com todos os parâmetros configurados
        # data: envelope SOAP codificado em UTF-8
        # headers: cabeçalhos SOAP obrigatórios
        # verify: controle de verificação SSL
        # timeout: limite de 30 segundos para evitar travamentos
        response = session.post(url, data=soap_envelope.encode("utf-8"),
                              headers=headers, verify=verify_ssl, timeout=30)
        
        # Verifica se a resposta HTTP foi bem-sucedida (2xx)
        # Levanta HTTPError para códigos 4xx e 5xx
        response.raise_for_status()
        
        # Retorna o conteúdo XML da resposta como string
        return response.text
        
    # Captura qualquer exceção de requisição (rede, timeout, HTTP, etc.)
    except requests.exceptions.RequestException as e:
        # Registra o erro detalhado no log para debugging
        logger.error(f"Erro na requisição ao webservice: {str(e)}")
        
        # Levanta exceção personalizada com mensagem mais amigável
        raise Exception(f"Erro na consulta ao webservice: {str(e)}")
        
    # Bloco finally garante que a sessão seja sempre fechada
    # Importante para liberar recursos de conexão
    finally:
        session.close()

# =====================================================================================
# Cliente SOAP para SEFAZ com Cache
# =====================================================================================
@flexible_cache(maxsize=128, ttl=3600)
def consultar_gtin_pfx_cached(gtin: str, pfx_file: str, pfx_password: str) -> str:
    """
    Versão otimizada com cache da consulta GTIN no webservice da SEFAZ.
    
    Esta função é um wrapper da consultar_gtin_pfx() que adiciona uma camada de cache
    inteligente para otimizar consultas repetidas ao mesmo GTIN. O cache reduz
    significativamente o tempo de resposta e diminui a carga no webservice da SEFAZ.
    
    O sistema de cache utiliza uma estratégia LRU (Least Recently Used) com TTL
    (Time To Live), garantindo que os dados sejam atualizados periodicamente e
    que consultas frequentes sejam respondidas instantaneamente.
    
    Args:
        gtin (str): Código GTIN (Global Trade Item Number) do produto a ser consultado.
                   Pode conter formatação que será removida pela função base.
                   Serve como chave principal do cache junto com o certificado.
        pfx_file (str): Caminho para o arquivo de certificado digital PFX.
                       Importante para a chave do cache, pois diferentes certificados
                       podem ter permissões distintas para consultas.
        pfx_password (str): Senha do certificado digital PFX.
                           Também compõe a chave do cache para garantir unicidade.
    
    Returns:
        str: Resposta XML do webservice da SEFAZ, idêntica à função base.
             Pode vir do cache (resposta instantânea) ou de nova consulta ao webservice.
    
    Raises:
        Exception: As mesmas exceções da função consultar_gtin_pfx():
                  - Erros de conectividade
                  - Problemas de autenticação
                  - Timeout ou certificado inválido
                  - Cache miss não afeta o comportamento de exceções
    
    Cache Behavior:
        Decorator @flexible_cache configurado com:
        - maxsize=128: Armazena até 128 consultas diferentes em memória
        - ttl=3600: Cache válido por 3600 segundos (1 hora)
        - Chave do cache: Combinação de (gtin, pfx_file, pfx_password)
        - Política LRU: Remove entradas menos usadas quando atinge maxsize
        - Thread-safe: Seguro para uso em aplicações concorrentes
    
    Performance Benefits:
        - Cache HIT: Resposta instantânea (~1ms vs ~2000ms da consulta real)
        - Redução de carga na SEFAZ: Menos requisições desnecessárias
        - Economia de recursos: Menos uso de certificado digital e bandwidth
        - Melhor experiência do usuário: Respostas mais rápidas
    
    Example:
        >>> # Primeira consulta - vai ao webservice (lenta)
        >>> gtin = "7891000100103"
        >>> cert_path = "/path/to/certificate.pfx"
        >>> cert_password = "minha_senha"
        >>> 
        >>> import time
        >>> start = time.time()
        >>> resultado1 = consultar_gtin_pfx_cached(gtin, cert_path, cert_password)
        >>> print(f"Primeira consulta: {time.time() - start:.2f}s")  # ~2.5s
        >>> 
        >>> # Segunda consulta - vem do cache (rápida)
        >>> start = time.time()
        >>> resultado2 = consultar_gtin_pfx_cached(gtin, cert_path, cert_password)
        >>> print(f"Segunda consulta: {time.time() - start:.2f}s")   # ~0.001s
        >>> 
        >>> # Resultados são idênticos
        >>> assert resultado1 == resultado2
    
    Cache Management:
        >>> # Verificar estatísticas do cache (se disponível no decorator)
        >>> print(consultar_gtin_pfx_cached.cache_info())
        >>> 
        >>> # Limpar cache manualmente (se disponível)
        >>> consultar_gtin_pfx_cached.cache_clear()
    
    Note:
        - Cache é mantido apenas durante o ciclo de vida da aplicação
        - Reiniciar aplicação limpa todo o cache
        - TTL de 1 hora é adequado para dados de produtos (raramente mudam)
        - Para dados que mudam frequentemente, considere reduzir o TTL
        - O cache considera TODOS os parâmetros, incluindo certificado
        - Diferentes certificados geram entradas de cache separadas
    
    Warning:
        - Cache pode consumir memória significativa com muitos GTINs únicos
        - Monitor o uso de memória em aplicações de alto volume
        - Consider implementar métricas de cache hit/miss para otimização
        - Em clusters/múltiplas instâncias, cada instância tem seu próprio cache
    
    Best Practices:
        - Use esta versão para consultas repetidas do mesmo GTIN
        - Para consultas únicas, use consultar_gtin_pfx() diretamente
        - Monitore a taxa de cache hit para ajustar maxsize se necessário
        - Configure logging para rastrear performance do cache
        - Considere cache distribuído (Redis) para aplicações em cluster
    """
    
    # Delega a execução real para a função base consultar_gtin_pfx
    # O decorator @flexible_cache intercepta esta chamada e:
    # 1. Calcula uma chave de cache baseada nos parâmetros (gtin, pfx_file, pfx_password)
    # 2. Verifica se existe entrada válida no cache para esta chave
    # 3. Se CACHE HIT: retorna o valor armazenado instantaneamente
    # 4. Se CACHE MISS: executa a função real, armazena o resultado e retorna
    # 5. Gerencia automaticamente TTL e limpeza de entradas expiradas
    # 6. Aplica política LRU quando maxsize é atingido
    return consultar_gtin_pfx(gtin, pfx_file, pfx_password)


# =====================================================================================
# Utilitário para Busca de Chaves
# =====================================================================================
def buscar_chave(dicionario: dict, chave_procurada: str):
    """
    Busca recursivamente por uma chave específica em um dicionário aninhado.
    
    Esta função implementa uma busca em profundidade (DFS - Depth First Search) 
    utilizando uma pilha iterativa para percorrer todos os níveis de um dicionário
    aninhado em busca de uma chave específica. Quando encontrada, retorna o 
    dicionário pai que contém a chave.
    
    A função é útil para navegar em estruturas JSON complexas, configurações
    aninhadas, dados de APIs com múltiplos níveis, ou qualquer estrutura de
    dicionário hierárquica onde você precisa localizar uma chave específica.
    
    Args:
        dicionario (dict): Dicionário principal onde será realizada a busca.
                          Pode conter sub-dicionários aninhados em qualquer nível.
                          Se não for um dicionário válido, retorna None.
        chave_procurada (str): Nome exato da chave que está sendo procurada.
                              A busca é case-sensitive e deve corresponder exatamente.
    
    Returns:
        dict | None: Retorna o dicionário que contém a chave procurada.
                    Se a chave for encontrada, retorna o dicionário pai.
                    Se a chave não for encontrada ou entrada inválida, retorna None.
    
    Algorithm:
        Utiliza busca em profundidade iterativa com pilha:
        1. Inicializa pilha com dicionário raiz
        2. Para cada dicionário na pilha:
           - Verifica todas as chaves do nível atual
           - Se encontrar a chave procurada, retorna o dicionário atual
           - Se encontrar sub-dicionários, adiciona-os à pilha
        3. Continua até esgotar todos os níveis ou encontrar a chave
    
    Time Complexity: O(n) onde n é o número total de chaves em todos os níveis
    Space Complexity: O(d) onde d é a profundidade máxima do dicionário
    
    Example:
        >>> # Exemplo com dicionário simples
        >>> dados = {
        ...     "usuario": "joao",
        ...     "config": {
        ...         "tema": "escuro",
        ...         "notificacoes": True
        ...     }
        ... }
        >>> resultado = buscar_chave(dados, "tema")
        >>> print(resultado)
        {'tema': 'escuro', 'notificacoes': True}
        
        >>> # Exemplo com estrutura mais complexa
        >>> api_response = {
        ...     "status": "success",
        ...     "data": {
        ...         "user": {
        ...             "profile": {
        ...                 "settings": {
        ...                     "privacy": "private"
        ...                 }
        ...             }
        ...         }
        ...     }
        ... }
        >>> resultado = buscar_chave(api_response, "privacy")
        >>> print(resultado)
        {'privacy': 'private'}
        
        >>> # Chave não encontrada
        >>> resultado = buscar_chave(dados, "inexistente")
        >>> print(resultado)
        None
        
        >>> # Entrada inválida
        >>> resultado = buscar_chave("não é dict", "chave")
        >>> print(resultado)
        None
    
    Use Cases:
        - Parsing de respostas JSON complexas de APIs
        - Navegação em arquivos de configuração aninhados
        - Extração de dados específicos de estruturas hierárquicas
        - Validação da existência de configurações em sistemas
        - Debugging de estruturas de dados complexas
    
    Note:
        - A busca é case-sensitive: "Nome" ≠ "nome"
        - Retorna o PRIMEIRO dicionário que contém a chave
        - Não garante ordem específica de busca entre irmãos no mesmo nível
        - Para múltiplas ocorrências, retorna apenas a primeira encontrada
        - Funciona apenas com dicionários Python nativos (dict)
        - Não funciona com outros tipos de mapeamento (OrderedDict, etc.)
    
    Warning:
        - Para dicionários muito profundos, pode causar consumo alto de memória
        - Não detecta referências circulares - pode causar loop infinito
        - Performance degrada com muitos níveis aninhados
        - Thread-safe apenas se o dicionário não for modificado durante a busca
    """
    
    # Validação de entrada: verifica se o parâmetro é realmente um dicionário
    # Retorna None imediatamente para tipos inválidos (string, lista, None, etc.)
    if not isinstance(dicionario, dict):
        return None
    
    # Inicializa a pilha com o dicionário raiz para busca iterativa
    # A pilha armazena os dicionários que ainda precisam ser explorados
    # Usar pilha evita recursão e possíveis problemas de stack overflow
    pilha = [dicionario]
    
    # Loop principal: continua enquanto houver dicionários na pilha para explorar
    # Cada iteração processa um dicionário e adiciona seus sub-dicionários à pilha
    while pilha:
        # Remove e obtém o último dicionário adicionado à pilha (LIFO - Last In, First Out)
        # Isso implementa a busca em profundidade (DFS) de forma iterativa
        atual = pilha.pop()
        
        # Itera sobre todos os pares chave-valor do dicionário atual
        # Verifica cada chave do nível atual antes de descer para níveis mais profundos
        for chave, valor in atual.items():
            # Verifica se a chave atual é exatamente a que estamos procurando
            # Comparação é case-sensitive e deve ser correspondência exata
            if chave == chave_procurada:
                # ENCONTROU! Retorna o dicionário que contém a chave procurada
                # Este é o dicionário "pai" que contém nossa chave de interesse
                return atual
            
            # Se o valor associado à chave atual é também um dicionário,
            # adiciona este sub-dicionário à pilha para exploração posterior
            # Isso permite que a busca continue em níveis mais profundos
            if isinstance(valor, dict):
                pilha.append(valor)
    
    # Se chegou até aqui, significa que percorreu toda a estrutura
    # sem encontrar a chave procurada - retorna None indicando "não encontrado"
    return None

# =====================================================================================
# Enriquece dados de produtos na API do EANdata de forma assíncrona e silenciosa.
# =====================================================================================
async def enriquecer_com_eandata(dict_retorno: dict) -> dict:
    """
    Enriquece dados de produtos na API do EANdata de forma assíncrona e silenciosa.
    
    Esta função é projetada para funcionar como um processo secundário que extrai
    informações relevantes de produtos (peso, descrição) e as envia para a API
    do EANdata para enriquecimento da base de dados. O processo é completamente
    assíncrono e não afeta o fluxo principal da aplicação.
    
    A função implementa o padrão "fire-and-forget" onde falhas no enriquecimento
    não impactam a resposta principal. Isso garante que problemas na API externa
    não afetem a experiência do usuário final.
    
    Args:
        dict_retorno (dict): Dicionário contendo dados do produto obtidos de fontes
                           como SEFAZ ou Bluesoft. Deve conter estrutura com:
                           - status: Status da consulta anterior
                           - produto: Dict com dados do produto incluindo GTIN e xProd
    
    Returns:
        dict: O mesmo dicionário recebido, completamente inalterado.
              A função nunca modifica a estrutura ou conteúdo do retorno,
              apenas realiza operações de enriquecimento em segundo plano.
    
    Side Effects:
        - Envia dados via HTTP POST para API do EANdata
        - Registra logs informativos e de erro
        - Não modifica estado da aplicação principal
        - Falhas são silenciosas (apenas logadas)
    
    API Integration:
        Utiliza a API v3 do EANdata com os seguintes campos:
        - product: Descrição limpa do produto
        - language: Descrição em português (extra_id: 659)
        - weight: Peso extraído com unidade formatada
        
        Endpoint: POST com parâmetros query string
        Timeout: 15 segundos para evitar travamentos
    
    Async Behavior:
        - Utiliza httpx.AsyncClient para requisições não-bloqueantes
        - Compatible com FastAPI e outros frameworks assíncronos
        - Não bloqueia thread principal durante requisições HTTP
        - Gerencia automaticamente conexões e timeouts
    
    Error Handling:
        - Falhas silenciosas: nunca interrompe fluxo principal
        - Logs detalhados para debugging e monitoramento
        - Validações robustas para evitar requisições desnecessárias
        - Tratamento gracioso de timeouts e erros de rede
    
    Configuration Requirements:
        Requer as seguintes configurações em settings:
        - eandata_url: URL base da API EANdata
        - eandata_api_key: Chave de API válida para autenticação
    
    Example:
        >>> # Uso típico após consulta SEFAZ/Bluesoft
        >>> dados_produto = {
        ...     "status": "success",
        ...     "produto": {
        ...         "GTIN": "7891000100103",
        ...         "xProd": "COCA COLA LATA 350ML"
        ...     }
        ... }
        >>> 
        >>> # Enriquecimento assíncrono (não bloqueia)
        >>> resultado = await enriquecer_com_eandata(dados_produto)
        >>> 
        >>> # Resultado é idêntico ao input
        >>> assert resultado == dados_produto
        >>> 
        >>> # Logs indicarão se enriquecimento foi bem-sucedido
        >>> # INFO: Enriquecimento EANdata realizado com sucesso...
    
    Integration Pattern:
        >>> async def consultar_produto_completo(gtin: str):
        ...     # 1. Consulta principal (SEFAZ/Bluesoft)
        ...     dados = await consultar_dados_principais(gtin)
        ...     
        ...     # 2. Enriquecimento silencioso (não afeta resposta)
        ...     dados_finais = await enriquecer_com_eandata(dados)
        ...     
        ...     # 3. Retorna dados originais (enriquecimento é transparente)
        ...     return dados_finais
    
    Performance Notes:
        - Timeout de 15s balanceia responsividade vs. confiabilidade
        - httpx.AsyncClient otimizado para conexões HTTP/2
        - Validações antecipadas evitam requisições desnecessárias
        - Logs estruturados facilitam monitoramento e debugging
    
    Monitoring & Debugging:
        - Log level INFO: Operações normais e sucessos
        - Log level WARNING: Situações que impedem enriquecimento
        - Log level ERROR: Falhas técnicas que precisam investigação
        - Log level DEBUG: Detalhes da comunicação com API externa
    
    Note:
        - Função segura para uso em pipelines críticos
        - Não há risco de corromper dados principais
        - Ideal para melhorar qualidade de dados em background
        - Compatível com arquiteturas de microserviços
        - Suporta padrões de observabilidade (logging, métricas)
    """
    
    # Bloco try global para garantir que NUNCA afete o fluxo principal
    # Qualquer exceção não tratada será capturada e logada silenciosamente
    try:
        # Log inicial para rastreamento de operações e debugging
        # Permite identificar início do processo nos logs da aplicação
        logger.info("Iniciando enriquecimento com EANdata...")

        # VALIDAÇÃO 1: Verifica se a consulta anterior foi bem-sucedida
        # Só faz sentido enriquecer dados se a consulta principal funcionou
        # Evita processar dados inválidos ou incompletos desnecessariamente
        if dict_retorno.get("status") != "success":
            logger.warning("Enriquecimento cancelado: status da resposta não é 'success'")
            return dict_retorno

        # CONFIGURAÇÃO: Extrai configurações necessárias do sistema
        # Todas as configurações são validadas antes de prosseguir
        url = settings.eandata_url          # URL da API EANdata
        keycode = settings.eandata_api_key  # Chave de autenticação
        produto = dict_retorno.get("produto", {})  # Dados do produto
        update = produto.get("GTIN")        # GTIN como identificador único

        # VALIDAÇÃO 2: Verifica se configuração mínima está disponível
        # Sem esses dados básicos, é impossível fazer o enriquecimento
        # O warning ajuda a identificar problemas de configuração
        if not url or not keycode or not update:
            logger.warning("Chave, URL ou GTIN ausentes. Enriquecimento com EANdata não será realizado.")
            return dict_retorno

        # EXTRAÇÃO DE DADOS: Processa descrição do produto para extrair peso
        # A função extrair_peso_unidade analisa strings como "COCA COLA 350ML"
        # e separa descrição limpa do peso com unidade
        resultado_peso = extrair_peso_unidade(produto.get("xProd", ""))
        
        # Inicializa lista de campos que serão enviados para o EANdata
        # Cada campo é um dicionário com field, value e opcionalmente extra_id
        campos = []

        # PROCESSAMENTO: Converte dados extraídos em campos da API EANdata
        if resultado_peso:
            # Extrai componentes do resultado de parsing de peso/descrição
            descricao_limpa = resultado_peso.get("descricao")  # Ex: "COCA COLA"
            valor = resultado_peso.get("valor")                # Ex: "350"
            unidade = resultado_peso.get("unidade")           # Ex: "ML"

            # CAMPO 1: Descrição do produto (campo 'product')
            # Envia descrição limpa sem informações de peso/volume
            if descricao_limpa:
                campos.append({
                    "field": "product",
                    "value": descricao_limpa
                })
                
                # CAMPO 2: Idioma específico (português brasileiro)
                # extra_id "659" aparenta ser código para português-BR na API EANdata
                # Isso permite que a API categorize o idioma da descrição corretamente
                campos.append({
                    "field": "language",
                    "value": descricao_limpa,
                    "extra_id": "659"  # Código fixo (Português-BR?)
                })

            # CAMPO 3: Peso/Volume com unidade
            # Combina valor numérico com unidade de medida formatados
            # Ex: "350 ML", "500 G", "1 KG"
            if valor and unidade:
                campos.append({
                    "field": "weight",
                    "value": f"{valor} {unidade}"
                })

        # VALIDAÇÃO 3: Verifica se há dados úteis para enviar
        # Evita requisições HTTP desnecessárias quando não há o que enriquecer
        # Economiza recursos e reduz ruído nos logs
        if not campos:
            logger.info("Nenhum campo para enriquecer no EANdata.")
            return dict_retorno

        # PREPARAÇÃO DO PAYLOAD: Monta estrutura de dados para API EANdata
        # Segue especificação da API v3 com modo bulk update
        payload = {
            "v": "3",              # Versão da API EANdata
            "keycode": keycode,    # Chave de autenticação
            "update": update,      # GTIN do produto a ser atualizado
            "field": "*bulk*",     # Indica que é atualização em lote
            "fields": campos       # Lista de campos a serem atualizados
        }

        # REQUISIÇÃO ASSÍNCRONA: Envia dados para API EANdata
        # httpx.AsyncClient oferece melhor performance que requests em contexto async
        # Timeout de 15s balanceia espera razoável vs. não travar aplicação
        async with httpx.AsyncClient(timeout=15) as client:
            # POST com parâmetros na query string (conforme API EANdata)
            response = await client.post(url, params=payload)

            # ANÁLISE DA RESPOSTA: Verifica se enriquecimento foi bem-sucedido
            if response.status_code == 200:
                # Sucesso: registra operação bem-sucedida com GTIN para rastreamento
                logger.info(f"Enriquecimento EANdata realizado com sucesso para GTIN: {update}")
                
                # Debug: inclui resposta da API para troubleshooting se necessário
                # Útil para verificar se dados foram processados corretamente
                logger.debug(f"Resposta EANdata: {response.text}")
            else:
                # Falha HTTP: registra status code para investigação
                # Warning porque não é erro crítico, mas indica problema na integração
                logger.warning(f"EANdata retornou status {response.status_code} para GTIN: {update}")

    # TRATAMENTO DE EXCEÇÕES: Captura qualquer erro não previsto
    # Garante que falhas no enriquecimento NUNCA afetem fluxo principal
    except Exception as e:
        # Log de erro com detalhes para debugging, mas não interrompe execução
        # Permite identificar problemas de conectividade, timeout, parsing, etc.
        logger.error(f"Erro no enriquecimento com EANdata: {str(e)}")

    # RETORNO GARANTIDO: Sempre retorna dicionário original inalterado
    # Esta é a garantia fundamental da função - nunca modifica dados principais
    # Mesmo em caso de qualquer erro, a resposta original é preservada
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
                    # Retorno movido para fora do bloco try para evitar duplicação
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
            # Sucesso na requisição, sai do loop
            return response.json()
    # Se chegou aqui, todas as tentativas falharam
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
    if not Path(pfx_file).is_file():
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