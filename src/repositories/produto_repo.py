import os
from google.cloud import firestore

from src.core.logging_setup import logger
from src.core.config import settings

class ProdutoRepository:
    """Repositório para acesso a dados de Produto no Google Cloud Firestore."""
    
    def __init__(self, collection_name: str = "produtos"):
        self.collection_name = collection_name
        self._db = None

    @property
    def db(self):
        """Inicialização Lazy do cliente Firestore."""
        if self._db is None:
            try:
                cred_path = settings.google_application_credentials
                logger.debug(f"Tentando conectar ao Firestore usando: {cred_path}")
                
                if cred_path and os.path.exists(cred_path):
                    self._db = firestore.AsyncClient.from_service_account_json(cred_path)
                else:
                    # Fallback padrão (ex: ambiente Cloud Run)
                    self._db = firestore.AsyncClient()
                
                logger.info("Conexão com Firestore estabelecida com sucesso.")
            except Exception as e:
                logger.error(f"Erro crítico ao inicializar cliente Firestore: {e}")
                raise
        return self._db

    async def buscar_por_gtin(self, gtin: str) -> dict | None:
        """Busca um produto na base local do Firestore pelo GTIN.
        
        Args:
            gtin (str): Código GTIN/EAN.
            
        Returns:
            dict | None: Dados do produto se encontrado, None caso contrário.
        """
        try:
            doc_ref = self.db.collection(self.collection_name).document(gtin)
            doc = await doc_ref.get()
            if doc.exists:
                logger.info(f"CACHE HIT (Firestore) para GTIN: {gtin}")
                return doc.to_dict()
            return None
        except Exception as e:
            logger.warning(f"Erro ao buscar no Firestore para GTIN {gtin}: {e}")
            return None

    async def salvar(self, gtin: str, dados_produto: dict):
        """Salva ou atualiza os dados de um produto no Firestore.
        
        Args:
            gtin (str): Código GTIN/EAN.
            dados_produto (dict): Dados do produto mapeados em dicionário.
        """
        try:
            doc_ref = self.db.collection(self.collection_name).document(gtin)
            # Flag de última atualização do DB
            documento = {
                "gtin": gtin,
                "data_atualizacao": firestore.SERVER_TIMESTAMP,
                **dados_produto
            }
                
            await doc_ref.set(documento)
            logger.info(f"Dados salvos no Firestore com sucesso para GTIN: {gtin}")
        except Exception as e:
            logger.error(f"Erro ao salvar no Firestore para GTIN {gtin}: {e}")

    async def test_connection(self) -> bool:
        """Realiza um teste de conectividade simples com o Firestore.
        
        Returns:
            bool: True se a conexão estiver ativa, False caso contrário.
        """
        try:
            # Tenta apenas listar um documento de forma limitada para checar permissão/conexão
            async for _ in self.db.collection(self.collection_name).limit(1).stream():
                break
            return True
        except Exception as e:
            logger.error(f"Falha no teste de conexão com Firestore: {e}")
            return False

# Instância global (Singleton pattern simplificado)
produto_repository = ProdutoRepository()
