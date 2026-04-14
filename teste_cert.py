import os
import sys
from requests_pkcs12 import Pkcs12Adapter
from dotenv import load_dotenv

def testar_certificado():
    # Carrega as variáveis do .env atual
    load_dotenv()
    
    pfx_file = "cert.pfx"
    pfx_password = os.getenv("CERTIFICADO_SENHA")
    
    if not os.path.exists(pfx_file):
        print("ERRO: Arquivo cert.pfx não encontrado na pasta atual!")
        return

    if not pfx_password:
        print("ERRO: A senha CERTIFICADO_SENHA não foi encontrada no .env!")
        return

    print("=" * 50)
    print("Iniciando Teste de Validação do Certificado PFX...")
    print(f"Arquivo alvo: {pfx_file}")
    print("Testando Extração Segura e Descriptografia...")
    print("=" * 50)

    try:
        # A própria instância do Adapter obriga o código a abrir a criptografia do arquivo usando a senha
        adapter = Pkcs12Adapter(pkcs12_filename=pfx_file, pkcs12_password=pfx_password)
        
        print("\n✅ SUCESSO ABSOLUTO!")    
        print("O arquivo cert.pfx é válido, não está corrompido, e a senha configurada no seu .env bate perfeitamente com a criptografia dele.")
        print("Você pode prosseguir com o 'docker build' em segurança.")
    except Exception as e:
        print("\n❌ FALHA CRÍTICA - CERTIFICADO OU SENHA INVÁLIDOS!")
        print("Ocorreu o seguinte erro ao tentar abrir (provavelmente a senha está errada):")
        print(f"Erro: {str(e)}")

if __name__ == "__main__":
    testar_certificado()
