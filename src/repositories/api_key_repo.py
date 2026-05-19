import os
from google.cloud import firestore

from src.core.logging_setup import logger
from src.core.config import settings
from src.schemas.api_key import ApiKeyBase

class ApiKeyRepository:
    """Repositório para acesso a dados de chaves de API no Firestore."""
    
    def __init__(self, collection_name: str = "api_keys"):
        self.collection_name = collection_name
        self._db = None

    @property
    def db(self):
        """Inicialização Lazy do cliente Firestore."""
        if self._db is None:
            try:
                cred_path = settings.google_application_credentials
                if cred_path and os.path.exists(cred_path):
                    self._db = firestore.AsyncClient.from_service_account_json(cred_path)
                else:
                    self._db = firestore.AsyncClient()
            except Exception as e:
                logger.error(f"Erro ao inicializar cliente Firestore no ApiKeyRepository: {e}")
                raise
        return self._db

    async def buscar_chave(self, key_id: str) -> ApiKeyBase | None:
        """Busca uma chave de API pelo ID no Firestore.
        
        Args:
            key_id (str): A chave fornecida pelo cliente.
            
        Returns:
            ApiKeyBase | None: O objeto da chave se encontrada, ou None.
        """
        try:
            doc_ref = self.db.collection(self.collection_name).document(key_id)
            doc = await doc_ref.get()
            if doc.exists:
                data = doc.to_dict()
                # O ID do documento é a própria chave
                return ApiKeyBase(key_id=key_id, **data)
            return None
        except Exception as e:
            logger.warning(f"Erro ao buscar ApiKey {key_id}: {e}")
            return None

    async def salvar_chave(self, key_data: ApiKeyBase):
        """Salva uma nova chave no Firestore."""
        try:
            doc_ref = self.db.collection(self.collection_name).document(key_data.key_id)
            await doc_ref.set(key_data.model_dump(exclude={"key_id"}))
            logger.info(f"Chave de API do cliente {key_data.client_name} salva com sucesso.")
        except Exception as e:
            logger.error(f"Erro ao salvar ApiKey: {e}")

# Instância global (Singleton pattern simplificado)
api_key_repository = ApiKeyRepository()
