from fastapi import HTTPException, BackgroundTasks
import xmltodict
import traceback

from src.core.logging_setup import logger
from src.core.config import settings
from src.utils.helpers import validate_gtin
from src.utils.formatters import formatar_resposta_personalizada, formatar_resposta_bluesoft
from src.services.sefaz_client import consultar_gtin_pfx_cached_async
from src.services.bluesoft_client import consultar_bluesoft_cosmos
from src.services.eandata_client import enriquecer_com_eandata
from src.repositories.produto_repo import ProdutoRepository
from src.schemas.produto import ProdutoResponse

class ConsultarGtinUseCase:
    """Caso de uso para consulta de dados de produto via GTIN/EAN.
    
    Orquestra a busca no cache local (Firestore), SEFAZ, fallback na Bluesoft
    e enriquecimento de dados via EANdata.
    """
    
    def __init__(self, produto_repo: ProdutoRepository):
        self.produto_repo = produto_repo

    async def executar(self, codigo_gtin: str, background_tasks: BackgroundTasks) -> dict:
        """Executa a lógica de negócio para a consulta do GTIN.
        
        Args:
            codigo_gtin (str): Código numérico GTIN/EAN.
            background_tasks (BackgroundTasks): Objeto para enfileiramento de tarefas assíncronas.
            
        Returns:
            dict: Dicionário contendo os dados formatados do produto (compatível com ProdutoResponse).
            
        Raises:
            HTTPException: Em caso de GTIN inválido, não encontrado ou falhas internas.
        """
        logger.info(f"Iniciando Use Case de consulta para GTIN: {codigo_gtin}")
        
        if not validate_gtin(codigo_gtin):
            logger.warning(f"GTIN inválido recebido no Use Case: {codigo_gtin}")
            raise HTTPException(
                status_code=400, 
                detail="Código GTIN inválido. Verifique o tamanho e o dígito verificador."
            )

        # 1. Tenta buscar no banco de dados local (Cache no Firestore)
        produto_cache = await self.produto_repo.buscar_por_gtin(codigo_gtin)
        if produto_cache:
            logger.info(f"Retornando dados do cache para GTIN: {codigo_gtin}")
            # Mapeia os campos salvos de volta para o formato do ProdutoResponse
            return {
                "status": "success",
                "provider": "PAIRUS Soluções Tecnológicas",
                "cStat": "100",
                "xMotivo": "Consulta realizada com sucesso (Cache)",
                "produto": {
                    "GTIN": codigo_gtin,
                    "tpGTIN": produto_cache.get("tpGTIN"),
                    "xProd": produto_cache.get("xProd", "Descrição Indisponível"),
                    "NCM": produto_cache.get("NCM"),
                    "CEST": produto_cache.get("CEST"),
                    "fonte": produto_cache.get("fonte", "Cache Firestore"),
                    "atualizado": True,
                    "infoAdicional": produto_cache.get("infoAdicional")
                }
            }

        pfx_file = settings.certificado_caminho
        pfx_password = settings.certificado_senha

        # 2. Tenta a SEFAZ
        try:
            xml_retorno = await consultar_gtin_pfx_cached_async(codigo_gtin, pfx_file, pfx_password)
            if xml_retorno:
                dict_retorno = xmltodict.parse(xml_retorno)
                dict_retorno = await enriquecer_com_eandata(codigo_gtin, dict_retorno)
                resposta_sefaz = formatar_resposta_personalizada(dict_retorno, codigo_gtin)
                
                if resposta_sefaz.get("status") == "success":
                    logger.info(f"Consulta finalizada com sucesso para GTIN na SEFAZ: {codigo_gtin}")
                    produto_info = resposta_sefaz.get("produto", {})
                    info_adc = produto_info.get("infoAdicional", {})
                    
                    # Salva o objeto produto completo para manter consistência no cache
                    dados_salvar = {
                        **produto_info,
                        "fonte": "SEFAZ / EANdata"
                    }
                        
                    # Agenda o salvamento no banco de forma assíncrona
                    background_tasks.add_task(self.produto_repo.salvar, codigo_gtin, dados_salvar)
                    return resposta_sefaz
                else:
                    logger.warning(f"SEFAZ não encontrou o produto (cStat: {resposta_sefaz.get('cStat')}). Executando fallback Cosmos.")
            else:
                logger.warning(f"Resposta vazia da SEFAZ para GTIN: {codigo_gtin}. Executando fallback Cosmos.")
        except Exception as e:
            logger.error(f"Erro na consulta SEFAZ para GTIN {codigo_gtin}: {str(e)}")
            logger.debug(traceback.format_exc())

        # 3. Fallback: Bluesoft Cosmos
        logger.info(f"Tentando consulta via Bluesoft Cosmos para GTIN: {codigo_gtin}")
        try:
            dados_bluesoft = await consultar_bluesoft_cosmos(codigo_gtin)
            if dados_bluesoft:
                logger.info(f"Consulta Bluesoft Cosmos bem-sucedida para GTIN: {codigo_gtin}")
                resposta_cosmos = formatar_resposta_bluesoft(dados_bluesoft, codigo_gtin)
                
                produto_info = resposta_cosmos.get("produto", {})
                info_adc = produto_info.get("infoAdicional", {})
                
                # Salva o objeto produto completo do Cosmos
                dados_salvar = {
                    **produto_info,
                    "fonte": "Bluesoft Cosmos"
                }
                
                background_tasks.add_task(self.produto_repo.salvar, codigo_gtin, dados_salvar)
                return resposta_cosmos
            else:
                logger.warning(f"GTIN não encontrado na SEFAZ e na Bluesoft Cosmos: {codigo_gtin}")
                raise HTTPException(status_code=404, detail="GTIN não encontrado nas bases de dados consultadas.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro na consulta Bluesoft Cosmos para GTIN {codigo_gtin}: {str(e)}")
            logger.debug(traceback.format_exc())
            raise HTTPException(status_code=500, detail=f"Erro interno ao processar a requisição: {str(e)}")
