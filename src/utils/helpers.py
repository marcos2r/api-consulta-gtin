import re

def buscar_chave(dicionario, chave_procurada):
    """
    Busca recursivamente uma chave em estruturas aninhadas de dicionários/listas.
    """
    if isinstance(dicionario, dict):
        if chave_procurada in dicionario:
            return dicionario[chave_procurada]
        for v in dicionario.values():
            if isinstance(v, (dict, list)):
                resultado = buscar_chave(v, chave_procurada)
                if resultado is not None:
                    return resultado
    elif isinstance(dicionario, list):
        for item in dicionario:
            resultado = buscar_chave(item, chave_procurada)
            if resultado is not None:
                return resultado
    return None

def validate_gtin(gtin_code: str) -> bool:
    """
    Valida um código GTIN usando o algoritmo de dígito verificador.
    """
    if not isinstance(gtin_code, str) or not gtin_code.isdigit():
        return False
    if len(gtin_code) > 14 or len(gtin_code) not in [8, 12, 13, 14]:
        return False
    digito_verificador = int(gtin_code[-1])
    total = 0
    fator = 3
    for i in range(len(gtin_code) - 2, -1, -1):
        total += int(gtin_code[i]) * fator
        fator = 4 - fator
    digito_calculado = (10 - (total % 10)) % 10
    return digito_verificador == digito_calculado

def extrair_peso_unidade(descricao: str) -> dict:
    """
    Extrai o peso/unidade de uma string de descrição e normaliza para o inglês.
    """
    unidades = {
        "mg": "milligrams", "miligrama": "milligrams", "miligramas": "milligrams",
        "g": "grams", "grama": "grams", "gramas": "grams",
        "kg": "kilograms", "quilograma": "kilograms", "quilogramas": "kilograms",
        "t": "tons", "tonelada": "tons", "toneladas": "tons",
        "lb": "pounds", "lbs": "pounds", "libra": "pounds", "libras": "pounds",
        "oz": "ounces", "onça": "ounces", "onças": "ounces",
        "dwt": "pennyweight", "pennyweight": "pennyweight"
    }

    padrao = re.compile(
        r"(\d+(?:[.,]\d+)?)\s*"
        r"(mg|g|kg|t|lb|lbs|oz|dwt|"
        r"miligrama[s]?|grama[s]?|quilograma[s]?|tonelada[s]?|libra[s]?|onça[s]?|pennyweight)",
        re.IGNORECASE
    )

    match = padrao.search(descricao.lower())

    if match:
        valor, unidade_bruta = match.groups()
        unidade_normalizada = unidades.get(unidade_bruta.lower())

        if unidade_normalizada:
            trecho = match.group(0)
            descricao_limpa = re.sub(re.escape(trecho), '', descricao, flags=re.IGNORECASE).strip()
            descricao_limpa = re.sub(r'\s{2,}', ' ', descricao_limpa)

            return {
                "valor": float(valor.replace(",", ".")),
                "unidade": unidade_normalizada,
                "descricao": descricao_limpa
            }

    return {
        "valor": None,
        "unidade": None,
        "descricao": descricao
    }
