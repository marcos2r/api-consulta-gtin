import logging
import logging.config
import os
import glob
from datetime import datetime, timedelta
from pathlib import Path
from src.core.config import settings

# Define o diretório base do projeto
BASE_DIR = Path(__file__).parent.parent.parent.resolve()
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

log_filename = LOG_DIR / f"gtin_api_{datetime.now().strftime('%Y%m%d')}.log"

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "DEBUG" if settings.ambiente == "desenvolvimento" else "INFO",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "standard",
            "filename": str(log_filename),
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
            "level": "DEBUG" if settings.ambiente == "desenvolvimento" else "INFO",
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

def limpar_logs_antigos(dias_para_manter=30):
    logger.info(f"Iniciando limpeza de logs antigos (mantendo últimos {dias_para_manter} dias)")
    data_limite = datetime.now() - timedelta(days=dias_para_manter)
    padrao_arquivos = str(LOG_DIR / "gtin_api_*.log")
    arquivos = glob.glob(padrao_arquivos)
    contador_removidos = 0
    
    for arquivo_path in arquivos:
        try:
            nome_arquivo = Path(arquivo_path).name
            data_str = nome_arquivo.replace("gtin_api_", "").replace(".log", "")
            data_arquivo = datetime.strptime(data_str, "%Y%m%d")
            
            if data_arquivo < data_limite:
                os.remove(arquivo_path)
                logger.debug(f"Arquivo de log antigo removido: {nome_arquivo}")
                contador_removidos += 1
        except ValueError:
            logger.warning(f"Arquivo de log com formatação não esperada encontrado: {Path(arquivo_path).name}")
            
    logger.info(f"Limpeza de logs concluída. {contador_removidos} arquivos removidos.")
