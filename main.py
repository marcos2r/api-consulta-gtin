import requests
from requests_pkcs12 import Pkcs12Adapter
import xmltodict
import json
from fastapi import FastAPI, HTTPException
import os
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# Inicializa a aplicação FastAPI
app = FastAPI(
    title="API de Consulta GTIN",
    description="API para consulta de produtos através do código GTIN/EAN na base da SEFAZ",
    version="1.0.0",
    contact={
        "name": "MARCOS RICARDO RODRIGUES",
        "email": "bcc.marcos@gmail.com",
        "empresa": "PAIRUS Soluções Tecnológicas"  
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    }
)
"""
GTIN Query API

A FastAPI application for querying product information using GTIN/EAN codes from SEFAZ database.

Author: Marcos Ricardo Rodrigues <bcc.marcos@gmail.com>
Created: 2025-02-23
License: MIT
"""

def xml_to_json(xml_string):
    """
    Converte uma string XML para formato JSON.
    
    Args:
        xml_string (str): String contendo o XML a ser convertido
        
    Returns:
        str: JSON formatado ou mensagem de erro em caso de falha
        
    Raises:
        Exception: Erro durante a conversão do XML para JSON
    """
    try:
        # Converte XML para dictionary usando xmltodict
        xml_dict = xmltodict.parse(xml_string)
        # Converte dictionary para JSON formatado
        json_string = json.dumps(xml_dict, indent=2, ensure_ascii=False)
        return json_string
    except Exception as e:
        return f"Erro na conversão: {str(e)}"

def consultar_gtin_pfx(gtin, pfx_file, pfx_password):
    """
    Realiza a consulta do GTIN no webservice da SEFAZ utilizando certificado digital.
    
    Args:
        gtin (str): Código GTIN/EAN do produto a ser consultado
        pfx_file (str): Caminho completo para o arquivo do certificado digital (.pfx)
        pfx_password (str): Senha do certificado digital
        
    Returns:
        str: Resposta do webservice em formato XML
        
    Raises:
        Exception: Erro durante a consulta ao webservice
    """
    # URL do webservice da SEFAZ
    url = "https://dfe-servico.svrs.rs.gov.br/ws/ccgConsGTIN/ccgConsGTIN.asmx"

    # Monta o envelope SOAP para a requisição
    soap_envelope = '<?xml version="1.0" encoding="UTF-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap12:Header/><soap12:Body><ccgConsGTIN xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin"><nfeDadosMsg><consGTIN versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe"><GTIN>{}</GTIN></consGTIN></nfeDadosMsg></ccgConsGTIN></soap12:Body></soap12:Envelope>'.format(gtin)

    # Configura os headers da requisição
    headers = {
        "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.portalfiscal.inf.br/nfe/wsdl/ccgConsGtin/ccgConsGTIN"'
    }

    # Configura a sessão com o certificado digital
    session = requests.Session()
    session.mount('https://', Pkcs12Adapter(pkcs12_filename=pfx_file,
                                           pkcs12_password=pfx_password))

    # Realiza a requisição POST ao webservice
    response = session.post(
        url,
        data=soap_envelope.encode("utf-8"),
        headers=headers,
        verify=False,
        timeout=30
    )
    return response.text

@app.get("/gtin/{codigo_gtin}")
async def consultar_gtin(codigo_gtin: str):
    """
    Endpoint para consulta de produtos por GTIN.
    
    Args:
        codigo_gtin (str): Código GTIN/EAN do produto
        
    Returns:
        dict: Informações do produto em formato JSON
        
    Raises:
        HTTPException: Erro 500 em caso de falha na consulta ou configuração
    """
    try:
        # Obtém as configurações do certificado das variáveis de ambiente
        pfx_file = os.getenv("CERTIFICADO_CAMINHO")
        pfx_password = os.getenv("CERTIFICADO_SENHA")
        
        # Verifica se as configurações do certificado existem
        if not pfx_file or not pfx_password:
            raise HTTPException(
                status_code=500,
                detail="Configurações do certificado não encontradas no arquivo .env"
            )
        
        # Realiza a consulta no webservice
        xml_retorno = consultar_gtin_pfx(codigo_gtin, pfx_file, pfx_password)
        
        # Converte a resposta XML para JSON
        json_retorno = xml_to_json(xml_retorno)
        
        # Retorna o resultado em formato JSON
        return json.loads(json_retorno)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))