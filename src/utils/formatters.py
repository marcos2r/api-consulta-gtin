from datetime import datetime
from src.core.logging_setup import logger
from src.utils.helpers import buscar_chave

def formatar_resposta_personalizada(dict_retorno: dict, codigo_gtin: str) -> dict:
    try:
        resposta = {
            "status": "success",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "produto": {}
        }

        ret_cons_gtin = buscar_chave(dict_retorno, "retConsGTIN")
        if ret_cons_gtin:
            if ret_cons_gtin.get("xMotivo") == "Consulta realizada com sucesso":
                resposta["produto"] = {
                    "GTIN": ret_cons_gtin.get("GTIN", codigo_gtin),
                    "tpGTIN": ret_cons_gtin.get("tpGTIN", ""),
                    "xProd": ret_cons_gtin.get("xProd", "").upper(),
                    "NCM": ret_cons_gtin.get("NCM", ""),
                    "CEST": str(ret_cons_gtin.get("CEST", "")).zfill(7) if ret_cons_gtin.get("CEST") else "",
                    "fonte": "SEFAZ"
                }

                resposta["cStat"] = "100"
                resposta["xMotivo"] = "Consulta realizada com sucesso"

                # Enriquecimento EANdata
                if "eandata" in dict_retorno and "status" in dict_retorno["eandata"]:
                    eandata = dict_retorno["eandata"]
                    if eandata["status"].get("code") in ["200", "500"]:
                        resposta["produto"]["atualizado"] = True
                        if "product" in eandata and eandata["product"]:
                            produto_eandata = eandata["product"]
                            extras = {}

                            campo_mapping = {
                                "description": "xDesc",
                                "brand": "xMarca",
                                "category": "xCategoria",
                                "country": "xOrigem"
                            }
                            for campo_original, campo_nfe in campo_mapping.items():
                                if campo_original in produto_eandata and produto_eandata[campo_original]:
                                    extras[campo_nfe] = produto_eandata[campo_original]

                            # Lógica de fallback de imagem
                            ean_img_url = ""
                            try:
                                produtos_eandata = dict_retorno["eandata"].get("products", [])
                                if produtos_eandata:
                                    campos = produtos_eandata[0].get("fields", [])
                                    for campo in campos:
                                        if campo.get("field") == "product" and campo.get("status") == "ok":
                                            ean_img_url = produtos_eandata[0].get("img_url", "")
                            except Exception as e:
                                logger.warning(f"Erro ao extrair imagem da EANdata: {str(e)}")

                            if ean_img_url and not ean_img_url.lower().startswith("image error"):
                                extras["urlImagem"] = ean_img_url
                            elif "thumbnail" in dict_retorno and dict_retorno["thumbnail"]:
                                extras["urlImagem"] = dict_retorno["thumbnail"]

                            if extras:
                                resposta["produto"]["infoAdicional"] = extras
            else:
                resposta["status"] = "error"
                resposta["cStat"] = ret_cons_gtin.get("cStat", "999")
                resposta["xMotivo"] = ret_cons_gtin.get("xMotivo", "Erro na consulta SEFAZ")
                resposta["produto"] = None
                logger.warning(f"Erro SEFAZ: cStat={resposta['cStat']}, xMotivo={resposta['xMotivo']}")
        else:
            resposta["status"] = "error"
            resposta["cStat"] = "999"
            resposta["xMotivo"] = "Resposta da SEFAZ inválida ou sem retConsGTIN"
            resposta["produto"] = None
            logger.warning("Erro SEFAZ: XML não contém retConsGTIN")
        
        return resposta

    except Exception as e:
        logger.error(f"Erro ao formatar resposta personalizada: {str(e)}")
        return {
            "status": "error",
            "cStat": "999",
            "xMotivo": f"Erro ao formatar resposta: {str(e)}",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "produto": None
        }

def formatar_resposta_bluesoft(dados_bluesoft: dict, codigo_gtin: str) -> dict:
    try:
        if not dados_bluesoft:
            return None

        resposta = {
            "status": "success",
            "provider": "PAIRUS Soluções Tecnológicas",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cStat": "100",
            "xMotivo": "Consulta realizada com sucesso",
            "produto": {
                "GTIN": codigo_gtin,
                "tpGTIN": f"GTIN-{len(codigo_gtin)}",
                "xProd": dados_bluesoft.get("description", "").upper(),
                "NCM": dados_bluesoft.get("ncm", {}).get("code", "") if "ncm" in dados_bluesoft else "",
                "CEST": str(dados_bluesoft.get("cest", {}).get("code", "")).zfill(7) if dados_bluesoft.get("cest", {}).get("code") else "",
                "fonte": "Bluesoft Cosmos"
            }
        }

        info_adicional = {}
        if "brand" in dados_bluesoft and dados_bluesoft["brand"]:
            info_adicional["xMarca"] = dados_bluesoft["brand"].get("name", "")
        if "gpc" in dados_bluesoft and dados_bluesoft["gpc"]:
            info_adicional["xCategoria"] = dados_bluesoft["gpc"].get("description", "")
        if "thumbnail" in dados_bluesoft and dados_bluesoft["thumbnail"]:
            info_adicional["urlImagem"] = dados_bluesoft["thumbnail"]
        if "commercial_unit" in dados_bluesoft and dados_bluesoft["commercial_unit"]:
            info_adicional["unidComercial"] = dados_bluesoft["commercial_unit"].get("type_abbreviation", "")
        if "width" in dados_bluesoft and "height" in dados_bluesoft and "length" in dados_bluesoft:
            info_adicional["dimensoes"] = {
                "largura": dados_bluesoft.get("width", 0),
                "altura": dados_bluesoft.get("height", 0),
                "comprimento": dados_bluesoft.get("length", 0),
                "unidade": "mm"
            }
        if "net_weight" in dados_bluesoft:
            info_adicional["pesoLiquido"] = dados_bluesoft.get("net_weight", 0)
        if "gross_weight" in dados_bluesoft:
            info_adicional["pesoBruto"] = dados_bluesoft.get("gross_weight", 0)
        
        if info_adicional:
            resposta["produto"]["infoAdicional"] = info_adicional
            
        return resposta
    except Exception as e:
        logger.error(f"Erro ao formatar resposta da Bluesoft: {str(e)}")
        return None
