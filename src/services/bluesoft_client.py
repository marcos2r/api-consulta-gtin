import re
import httpx
import asyncio
from datetime import datetime
from src.core.logging_setup import logger
from src.core.config import settings

class TokenManager:
    """Gerenciador de tokens para a API Bluesoft Cosmos.
    
    Implementa um sistema de rotação de tokens para contornar limites diários (rate limit),
    garantindo que cada token não ultrapasse 25 consultas por dia.
    """
    def __init__(self):
        """Inicializa o gerenciador e carrega os tokens disponíveis na configuração."""
        self.tokens = []
        self.current_index = 0
        self.usage_count = {}
        self.last_reset_date = datetime.now().date()
        self.load_tokens()

    def load_tokens(self):
        """Lê as chaves de API da Bluesoft a partir das variáveis de ambiente."""
        main_token = settings.cosmos_api_token
        if main_token:
            self.tokens.append(main_token)
            self.usage_count[main_token] = 0
        i = 1
        while True:
            token = getattr(settings, f"cosmos_api_token_{i}", None)
            if not token:
                break
            self.tokens.append(token)
            self.usage_count[token] = 0
            i += 1
        logger.info(f"Carregados {len(self.tokens)} tokens para a API Bluesoft Cosmos")

    def get_token(self) -> str | None:
        """Obtém um token válido com limite diário não excedido.
        
        Caso tenha mudado de dia, reseta os contadores de uso automaticamente.
        
        Returns:
            str | None: Token disponível ou None se todos atingiram o limite.
        """
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

    def increment_usage(self, token: str):
        """Registra o uso de um token específico, incrementando seu contador diário.
        
        Args:
            token (str): O token utilizado.
        """
        if token in self.usage_count:
            self.usage_count[token] += 1
            logger.info(f"Token Bluesoft: {token[:8]}... - Uso: {self.usage_count[token]}/25")

    def reset_usage_counts(self):
        """Reinicia todos os contadores de uso (executado na virada do dia)."""
        for token in self.tokens:
            self.usage_count[token] = 0
        logger.info("Contadores de uso dos tokens Bluesoft resetados (novo dia)")

token_manager = TokenManager()

async def consultar_bluesoft_cosmos(codigo_gtin: str) -> dict | None:
    """Consulta informações do produto na API REST da Bluesoft Cosmos (Fallback).
    
    Utiliza httpx.AsyncClient para não bloquear o event loop. Lida automaticamente com erros
    de limite de requisições (429), acionando a rotação de token do TokenManager.
    
    Args:
        codigo_gtin (str): Código GTIN/EAN do produto.
        
    Returns:
        dict | None: Dicionário com os dados JSON da API, ou None em caso de falha/inexistência.
    """
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
                    token_manager.usage_count[current_token] = 25
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
    return None
