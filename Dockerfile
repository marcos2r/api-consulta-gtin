# Usar uma imagem base oficial do Python leve
FROM python:3.11-slim

# Definir variáveis de ambiente para otimizar o Python em containers
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Definir diretório de trabalho
WORKDIR /app

# Instalar dependências do sistema necessárias
# build-essential e libffi-dev podem ser necessários para cryptography/cffi
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiar apenas os arquivos de requisitos primeiro para aproveitar o cache do Docker
COPY requirements.txt .

# Instalar dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar o restante do código da aplicação
COPY . .

# Expor a porta que a aplicação irá rodar
EXPOSE 8000

# Comando para iniciar a aplicação usando Gunicorn com workers Uvicorn
# Ajuste o número de workers conforme necessário ou use variável de ambiente
CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000"]
