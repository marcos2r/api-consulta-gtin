import argparse
import secrets
import asyncio
from datetime import datetime
from src.schemas.api_key import ApiKeyBase
from src.repositories.api_key_repo import api_key_repository

def generate_secure_key(prefix: str = "gtin") -> str:
    """Gera uma chave criptograficamente segura."""
    token = secrets.token_urlsafe(32)
    return f"{prefix}_{token}"

async def main():
    parser = argparse.ArgumentParser(description="Gerar nova API Key no Firestore")
    parser.add_argument("client_name", type=str, help="Nome do cliente")
    parser.add_argument("--tier", type=str, default="basic", help="Plano do cliente (basic, pro)")
    parser.add_argument("--rate-limit", type=str, default="100/minute", help="Limite do slowapi")
    
    args = parser.parse_args()
    
    key_id = generate_secure_key()
    
    nova_chave = ApiKeyBase(
        key_id=key_id,
        client_name=args.client_name,
        tier=args.tier,
        rate_limit=args.rate_limit,
        created_at=datetime.now()
    )
    
    print(f"Gerando chave para o cliente: {args.client_name} ({args.tier} - {args.rate_limit})")
    await api_key_repository.salvar_chave(nova_chave)
    print("=" * 50)
    print(f"API KEY GERADA COM SUCESSO:")
    print(f"{key_id}")
    print("=" * 50)
    print("Forneça esta chave ao cliente. Ela deve ser enviada no cabeçalho HTTP: X-API-Key")

if __name__ == "__main__":
    asyncio.run(main())
