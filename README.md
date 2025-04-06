# API de Consulta GTIN

Esta API, construída com FastAPI, permite consultar informações de produtos por meio do código GTIN/EAN utilizando o webservice oficial da SEFAZ. Além disso, os dados são enriquecidos com informações complementares fornecidas pelo serviço EANdata, e a resposta é formatada seguindo um padrão compatível com a nomenclatura NF-e.

## Funcionalidades

- **Consulta de Produtos:** Realiza consultas no webservice da SEFAZ utilizando um certificado digital (formato PFX).
- **Enriquecimento de Dados:** Complementa os dados obtidos com informações adicionais do serviço EANdata.
- **Cache de Consultas:** Implementação de cache LRU para otimizar as requisições, armazenando até 128 consultas por 1 hora.
- **Resposta Personalizada:** Formatação da resposta no padrão utilizado em NF-e, facilitando a integração com outros sistemas.
- **Logging e Monitoramento:** Logs diários são gerados e automaticamente limpos após 30 dias para manter o ambiente organizado.
- **Endpoints de Saúde:** Endpoint para verificação do status da API.

## Requisitos

- Python 3.9 ou superior.
- Dependências (instaladas via `requirements.txt`):
  - FastAPI
  - uvicorn
  - requests
  - requests_pkcs12
  - xmltodict
  - python-dotenv
  - tenacity
  - Outras dependências necessárias para o projeto

Para instalar as dependências, execute:

```bash
pip install -r requirements.txt
```

## Configuração

1. **Arquivo de Ambiente (.env):**  
   Crie um arquivo `.env` na raiz do projeto e configure as seguintes variáveis:

   ```env
   CERTIFICADO_CAMINHO=/caminho/para/seu/certificado.pfx
   CERTIFICADO_SENHA=sua_senha_do_certificado
   EANDATA_API_KEY=sua_chave_api_eandata
   CONTATO_NOME=Seu Nome ou Suporte Técnico
   CONTATO_EMAIL=seu_email@exemplo.com
   EMPRESA_NOME=Nome da Sua Empresa
   AMBIENTE=desenvolvimento  # ou producao
   IGNORAR_SSL=true          # Apenas para ambiente de desenvolvimento
   ```

2. **Certificado Digital:**  
   Certifique-se de que o arquivo de certificado digital (.pfx) esteja disponível no caminho especificado em `CERTIFICADO_CAMINHO`.

## Execução

Para executar a API localmente, utilize o comando abaixo (substitua `main` pelo nome do arquivo, se necessário):

```bash
uvicorn main:app --reload
```

O parâmetro `--reload` é útil durante o desenvolvimento, pois recarrega a API a cada alteração no código.

## Endpoints

### Consulta de Produto

- **URL:** `/gtin/{codigo_gtin}`
- **Método:** `GET`
- **Descrição:** Consulta informações de um produto a partir do código GTIN/EAN.
- **Exemplo de Uso:**  
  ```http
  GET /gtin/7891234567890
  ```
- **Resposta:**  
  A resposta é formatada com as informações do produto e dados adicionais do EANdata, seguindo o padrão NF-e.

### Verificação de Saúde

- **URL:** `/health`A seguir, um exemplo de um arquivo **README.md** detalhado e profissional para a sua API:

---

# API de Consulta GTIN

A **API de Consulta GTIN** é uma solução robusta para consulta de produtos utilizando códigos GTIN/EAN. Ela integra a consulta ao webservice da SEFAZ com fallback para a API Bluesoft Cosmos, oferecendo enriquecimento dos dados via EANdata, cache flexível e gerenciamento avançado de tokens para maximizar a disponibilidade das consultas.

## Sumário

- [Recursos](#recursos)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso](#uso)
  - [Endpoints Principais](#endpoints-principais)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Logging e Cache](#logging-e-cache)
- [Gerenciamento de Tokens](#gerenciamento-de-tokens)
- [Deploy](#deploy)
- [Licença](#licença)
- [Contato](#contato)

## Recursos

- **Consulta de Produtos via GTIN/EAN:** Realiza consulta no webservice oficial da SEFAZ utilizando certificado digital.
- **Fallback para Bluesoft Cosmos:** Em caso de falha ou ausência de produto na SEFAZ, a API realiza uma consulta na API Bluesoft Cosmos.
- **Enriquecimento com EANdata:** Complementa os dados do produto com informações adicionais (descrição, marca, categoria, imagem e país de origem).
- **Cache Flexível:** Implementação de cache com TTL para reduzir a carga no servidor e melhorar a performance.
- **Gerenciamento de Tokens:** Rotação e controle de uso dos tokens da API Bluesoft Cosmos para maximizar o número de consultas diárias.
- **Endpoints de Saúde:** Endpoint dedicado para verificação da integridade e disponibilidade da API.

## Tecnologias Utilizadas

- **Linguagem:** Python 3.8+  
- **Framework Web:** [FastAPI](https://fastapi.tiangolo.com/)
- **Servidor ASGI:** [Uvicorn](https://www.uvicorn.org/)
- **Bibliotecas HTTP:** [requests](https://docs.python-requests.org/), [httpx](https://www.python-httpx.org/)
- **Certificação Digital:** [requests_pkcs12](https://pypi.org/project/requests-pkcs12/)
- **Manipulação de XML:** [xmltodict](https://github.com/martinblech/xmltodict)
- **Cache:** Decorador customizado com TTL (possível substituição por [cachetools](https://pypi.org/project/cachetools/))
- **Gerenciamento de Tokens:** Implementação customizada para rotação de tokens
- **Retry:** [tenacity](https://tenacity.readthedocs.io/en/latest/)
- **Configuração:** [Pydantic](https://pydantic-docs.helpmanual.io/) (utilizando `BaseSettings` – para uso com Pydantic 1.x)

## Instalação

1. **Clone o Repositório**

   ```bash
   git clone https://seurepositorio.com/api-consulta-gtin.git
   cd api-consulta-gtin
   ```

2. **Crie e Ative o Ambiente Virtual**

   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   ```

3. **Instale as Dependências**

   Crie um arquivo `requirements.txt` com as dependências necessárias ou instale-as manualmente:

   ```bash
   pip install fastapi uvicorn requests requests_pkcs12 xmltodict httpx tenacity pydantic
   ```

   **Atenção:** Caso utilize o Pydantic versão 2.x, ajuste a importação de `BaseSettings` conforme a [documentação oficial](https://docs.pydantic.dev/2.10/migration/#basesettings-has-moved-to-pydantic-settings) ou utilize uma versão anterior:

   ```bash
   pip install "pydantic<2.0"
   ```

## Configuração

Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis de ambiente (exemplo):

```dotenv
CERTIFICADO_CAMINHO=/caminho/para/seu/certificado.pfx
CERTIFICADO_SENHA=suasenha
EANDATA_API_KEY=sua_chave_eandata
COSMOS_API_TOKEN=sua_chave_principal_cosmos
COSMOS_API_TOKEN_1=sua_chave_adicional_cosmos
AMBIENTE=desenvolvimento
IGNORAR_SSL=true
CONTATO_NOME=Suporte Técnico
CONTATO_EMAIL=suporte@exemplo.com
EMPRESA_NOME=Minha Empresa
```

> **Observação:** Certifique-se de que os caminhos e chaves estejam corretamente configurados. Em ambiente de produção, mantenha a verificação SSL habilitada e use certificados válidos.

## Uso

Para iniciar a API em modo de desenvolvimento, execute:

```bash
uvicorn main:app --reload
```

A API ficará disponível no endereço [http://127.0.0.1:8000](http://127.0.0.1:8000).

### Endpoints Principais

- **Consulta GTIN:**  
  **URL:** `/gtin/{codigo_gtin}`  
  **Método:** `GET`  
  **Descrição:** Consulta informações do produto através do código GTIN/EAN.  
  **Exemplo de Uso:**

  ```bash
  curl -X GET "http://127.0.0.1:8000/gtin/7891234567890" -H "accept: application/json"
  ```

- **Health Check:**  
  **URL:** `/health`  
  **Método:** `GET`  
  **Descrição:** Verifica o status de saúde da API.  
  **Exemplo de Uso:**

  ```bash
  curl -X GET "http://127.0.0.1:8000/health" -H "accept: application/json"
  ```

## Estrutura do Projeto

```
api-consulta-gtin/
├── main.py           # Código principal da API (FastAPI, endpoints e lógica de negócio)
├── .env              # Variáveis de ambiente
├── requirements.txt  # Dependências do projeto
└── logs/             # Diretório onde os arquivos de log são armazenados
```

## Logging e Cache

- **Logging:**  
  A API utiliza um sistema de logging configurado via `logging.config.dictConfig`. Os logs são armazenados em arquivos rotativos no diretório `logs/` com tamanho máximo de 10 MB por arquivo e até 5 backups.

- **Cache:**  
  O decorator `flexible_cache` é utilizado para armazenar respostas de consultas GTIN por até 1 hora (TTL de 3600 segundos). Em ambientes de alta demanda, considere migrar para uma solução de cache distribuído, como o Redis.

## Gerenciamento de Tokens

A API implementa um sistema de gerenciamento e rotação de tokens para a API Bluesoft Cosmos.  
- **Rotação:** Quando um token atinge o limite diário de 25 consultas, a API alterna automaticamente para outro token disponível.  
- **Reset Diário:** Os contadores de uso são reiniciados a cada novo dia.

## Deploy

Para ambientes de produção, recomenda-se:

- Desabilitar o modo de recarregamento automático (`--reload`).
- Configurar um servidor ASGI robusto (por exemplo, utilizando Gunicorn em conjunto com Uvicorn Workers).
- Garantir que as variáveis de ambiente estejam devidamente configuradas e seguras.
- Configurar monitoramento e backups para os arquivos de log.

Exemplo de comando para produção:

```bash
uvicorn main:app --host 0.0.0.0 --port 80
```

## Licença

Este projeto está licenciado sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

## Contato

- **Nome:** MARCOS RICARDO RODRIGUES
- **Email:** bcc.marcos@gmail.com 
- **Empresa:** PAIRUS Soluções Tecnológicas