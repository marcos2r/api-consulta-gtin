# API de Consulta GTIN

Este projeto provê uma **API** que permite consultar informações de produtos a partir de seu **código GTIN/EAN**. A aplicação integra-se ao **Web Service ccgConsGTIN** da SEFAZ (SVRS), utilizando um **certificado digital em formato .pfx (PKCS#12)** para a comunicação segura (mútua) e retorna as informações em **JSON** através de uma API construída com **FastAPI**.

---

## Sumário

1. [Visão Geral](#visão-geral)  
2. [Tecnologias Utilizadas](#tecnologias-utilizadas)  
3. [Pré-requisitos](#pré-requisitos)  
4. [Instalação e Configuração](#instalação-e-configuração)  
   - [Clonando o Repositório](#clonando-o-repositório)  
   - [Variáveis de Ambiente (.env)](#variáveis-de-ambiente-env)  
   - [Instalando Dependências](#instalando-dependências)  
5. [Execução](#execução)  
6. [Uso da API](#uso-da-api)  
   - [Endpoint de Consulta GTIN](#endpoint-de-consulta-gtin)  
   - [Retorno e Estrutura de Resposta](#retorno-e-estrutura-de-resposta)  
7. [Exemplos de Requisição](#exemplos-de-requisição)  
8. [Licença](#licença)  
9. [Contato](#contato)  

---

## Visão Geral

O **código GTIN** (Global Trade Item Number), também conhecido como EAN, é um identificador internacional de produtos. A Nota Técnica 2022.001 do projeto NF-e institui o Web Service **ccgConsGTIN** para consulta centralizada de dados de produtos, mantido pela SEFAZ (SVRS) em parceria com a GS1 Brasil.

Nesta aplicação, você encontra:

- **FastAPI** para construção e documentação do endpoint REST/HTTP.  
- **requests + requests_pkcs12** para enviar requisições SOAP 1.2 ao webservice, usando um **arquivo de certificado digital** (.pfx).  
- **xmltodict** para converter a resposta SOAP/XML em dicionários Python e, posteriormente, em JSON.

A aplicação pode ser facilmente estendida para uso interno nas empresas que precisem consultar ou validar dados de produtos a partir do GTIN.

---

## Tecnologias Utilizadas

- **Python 3.9+** (compatível também com versões mais recentes do Python 3)  
- **FastAPI**: Framework web para criação de APIs rápidas e performáticas.  
- **requests**: Biblioteca para requisições HTTP.  
- **requests_pkcs12**: Extensão que permite usar arquivos .pfx/.p12 para autenticação mútua (mTLS).  
- **xmltodict**: Converte respostas XML em dicionário Python.  
- **dotenv**: Facilita a leitura de variáveis de ambiente de um arquivo `.env`.

---

## Pré-requisitos

- **Python 3.9+** instalado em seu sistema.  
- **Certificado Digital em formato .pfx (PKCS#12)**, contendo o CNPJ ou CPF do emissor de NF-e/NFC-e.  
- **Conta e permissões** adequadas para instalar pacotes Python (ou uso de virtualenv).

---

## Instalação e ConfiguraçãoS

### Clonando o Repositório

```bash
git clone https://github.com/SeuUsuario/api-consulta-gtin.git
cd api-consulta-gtin
```

---

### Variáveis de Ambiente (.env)

Crie um arquivo .env na raiz do projeto e defina as seguintes variáveis:

```bash
SEFAZ_API_URL=https://dfe-portal.svrs.rs.gov.br/ws/ccgConsGTIN/ccgConsGTIN.asmx
CERTIFICATE_PATH=path/to/your/certificate.pfx
CERTIFICATE_PASSWORD=your_certificate_password
```	

---

### Instalando Dependências

Crie um ambiente virtual e instale as dependências:

```bash
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```
---

## Execução

Para iniciar a aplicação, execute:

```bash
uvicorn main:app --reload
```
A aplicação estará disponível em http://localhost:8000 .

---

## Uso da API

### Endpoint de Consulta GTIN

- URL: /gtin/{codigo_gtin}:
- Método: GET
- Parâmetros: codigo_gtin (obrigatório)

---

### Retorno e Estrutura de Resposta

Resposta em formato JSON.

```json
{
    "status": "success",
    "data": {
        "gtin": "7891234567890",
        "produto": "Nome do Produto",
        "marca": "Marca do Produto",
        "ncm": "12345678"
    }
}
```
---

## Exemplos de Requisição

cURL

```bash 
curl -X GET "http://localhost:8000/consulta?gtin=7891234567890"
```	
Python

```python
import requests

response = requests.get('http://localhost:8000/consulta', params={'gtin': '7891234567890'})
print(response.json())
```
---

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.

## Contato

- **Nome**: Marcos Ricardo Rodrigues
- **E-mail**: bcc.marcos@gmail.com 

