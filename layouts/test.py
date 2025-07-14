#!/usr/bin/env python3
"""
Decodificador completo de QR Code - Base45 + ZLIB + JSON
Baseado no padrão EU Digital Green Certificate
"""

import base45
import zlib
import json
from typing import Optional


def decode_qr_code(qr_data: str) -> Optional[dict]:
    """
    Decodifica completamente um QR code Base45 + ZLIB

    Args:
        qr_data: String Base45 do QR code

    Returns:
        Dict com dados JSON decodificados ou None em caso de erro
    """

    print("=== DECODIFICAÇÃO COMPLETA QR CODE ===")
    print(f"Input Base45: {len(qr_data)} caracteres")

    try:
        # Passo 1: Decodificar Base45
        print("\n1. Decodificando Base45...")
        zlib_data = base45.b45decode(qr_data)
        print(f"   ✓ Base45 decodificado: {len(zlib_data)} bytes")

        # Debug: mostrar primeiros bytes
        hex_bytes = ' '.join(f'{b:02x}' for b in zlib_data[:10])
        print(f"   Primeiros bytes (hex): {hex_bytes}")

        # Passo 2: Descomprimir ZLIB
        print("\n2. Descomprimindo ZLIB...")
        json_data = zlib.decompress(zlib_data)
        json_string = json_data.decode('utf-8')
        print(f"   ✓ ZLIB descomprimido: {len(json_string)} caracteres")

        # Passo 3: Parse JSON
        print("\n3. Fazendo parse do JSON...")
        json_object = json.loads(json_string)
        print("   ✓ JSON válido!")

        # Passo 4: Pretty print
        pretty_json = json.dumps(json_object, indent=2, ensure_ascii=False)

        print("\n" + "=" * 50)
        print("🎉 DADOS DECODIFICADOS COM SUCESSO!")
        print("=" * 50)
        print(pretty_json)
        print("=" * 50)

        return json_object

    except Exception as e:
        print(f"❌ Erro na decodificação: {e}")
        import traceback
        traceback.print_exc()
        return None


def analyze_qr_structure(qr_data: str) -> None:
    """
    Analisa a estrutura do QR code sem decodificar completamente
    """
    print("\n=== ANÁLISE ESTRUTURAL ===")

    # Verificar caracteres Base45 válidos
    valid_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    invalid_chars = [c for c in qr_data if c not in valid_chars]

    print(f"Tamanho: {len(qr_data)} caracteres")
    print(f"Caracteres inválidos: {len(invalid_chars)}")

    if invalid_chars:
        print(f"Inválidos encontrados: {set(invalid_chars)}")
    else:
        print("✓ Todos os caracteres são válidos para Base45")

    # Verificar limites de QR code
    qr_limits = {
        "L (7%)": 2953,
        "M (15%)": 2331,
        "Q (25%)": 1663,
        "H (30%)": 1273
    }

    print("\nCompatibilidade com QR code:")
    for level, limit in qr_limits.items():
        fits = "✓" if len(qr_data) <= limit else "❌"
        print(f"  {fits} Nível {level}: {limit} chars")


def decode_step_by_step(qr_data: str) -> None:
    """
    Decodifica passo a passo mostrando cada etapa
    """
    print("=== DECODIFICAÇÃO PASSO A PASSO ===")

    try:
        # Passo 1: Base45
        print("Passo 1: Decodificando Base45...")
        zlib_data = base45.b45decode(qr_data)
        print(f"  Resultado: {len(zlib_data)} bytes")
        print(f"  Primeiros 20 bytes: {zlib_data[:20]}")

        # Verificar cabeçalho ZLIB
        if len(zlib_data) >= 2:
            header = (zlib_data[0] << 8) | zlib_data[1]
            is_zlib = (header % 31 == 0) and ((zlib_data[0] & 0x0F) == 8)
            print(f"  Cabeçalho ZLIB válido: {'✓' if is_zlib else '❌'}")

        # Passo 2: ZLIB
        print("\nPasso 2: Descomprimindo ZLIB...")
        json_bytes = zlib.decompress(zlib_data)
        json_string = json_bytes.decode('utf-8')
        print(f"  Resultado: {len(json_string)} caracteres")
        print(f"  Primeiros 100 chars: {json_string[:100]}...")

        # Passo 3: JSON
        print("\nPasso 3: Validando JSON...")
        json_obj = json.loads(json_string)
        print(f"  Chaves principais: {list(json_obj.keys())}")

        if 'credential' in json_obj:
            cred = json_obj['credential']
            print(f"  Tipo de credential: {cred.get('type', 'N/A')}")

            if 'credentialSubject' in cred:
                subject = cred['credentialSubject']
                print(f"  Subject keys: {list(subject.keys())}")
                if 'nome' in subject:
                    print(f"  Nome: {subject['nome']}")
                if 'id' in subject:
                    print(f"  ID: {subject['id']}")

        print("\n✓ Decodificação completa bem-sucedida!")

    except Exception as e:
        print(f"❌ Erro: {e}")


def main():
    """Função principal - teste com os dados reais"""

    # Seus dados Base45 do QR code
    qr_data = """6BFG+H/.PIU0/32P0C0PVAT8%AP2N260K%MS2KB1LH1UR$51L9.4RRMFGUT.XMA70I24FMIUN6B9RUWTXZUTCDKC34YOED63BENR5W2R+%45SG:VIR.5T*4UVK5C49TM/580D7GT3%OH:TVRSSALDKVTUW2NR*OSBO/*E/:5BDBCVG 0K9TSRK8+%H17N 0U3/M+CJCD4BM044W+$E9$E*/D2S9X26T.OYSVX*RQ/H+LK2NU++H$E68GOUK68BHJLL*$Q$V254ROG88/J.FT8+2RM5%1TO3L6LSRK06-D$5H/VH+NKY KET0%7R2UN.ICXZA6-A+B1Q37HMTERQHVCKGADFP8I7TASF:2LB114QL1C7W9QH2I:LAVIW7A+MD+LAAZPSHR+A2IS2K*SCK0ZL9AU7MBCMEKVVWFNQY0DRJN*N4C3Z9POGMP1KKVFJ8S53R8%NG908DMV3U370S0RL0"""

    print("🚀 INICIANDO DECODIFICAÇÃO DOS SEUS DADOS")
    print("=" * 60)

    # Análise estrutural
    analyze_qr_structure(qr_data)

    # Decodificação passo a passo
    decode_step_by_step(qr_data)

    # Decodificação completa
    result = decode_qr_code(qr_data)

    if result:
        print("\n🎉 MISSÃO CUMPRIDA!")
        print("Seus dados foram decodificados com sucesso!")

        # Estatísticas finais
        if 'credential' in result:
            cred = result['credential']
            print(f"\n📊 RESUMO:")
            print(f"Tipo: {cred.get('type', 'N/A')}")
            print(f"Emissor: {cred.get('issuer', 'N/A')}")
            print(f"Data emissão: {cred.get('issuanceDate', 'N/A')}")

            if 'credentialSubject' in cred:
                subject = cred['credentialSubject']
                print(f"Subject ID: {subject.get('id', 'N/A')}")
                print(f"Nome: {subject.get('nome', 'N/A')}")
                print(f"Situação: {subject.get('situacaoSolicitacao', 'N/A')}")
    else:
        print("\n❌ Não foi possível decodificar os dados")


# Função para teste rápido
def quick_test():
    """Teste rápido - só mostrar o JSON final"""
    qr_data = """6BFG+H/.PIU0/32P0C0PVAT8%AP2N260K%MS2KB1LH1UR$51L9.4RRMFGUT.XMA70I24FMIUN6B9RUWTXZUTCDKC34YOED63BENR5W2R+%45SG:VIR.5T*4UVK5C49TM/580D7GT3%OH:TVRSSALDKVTUW2NR*OSBO/*E/:5BDBCVG 0K9TSRK8+%H17N 0U3/M+CJCD4BM044W+$E9$E*/D2S9X26T.OYSVX*RQ/H+LK2NU++H$E68GOUK68BHJLL*$Q$V254ROG88/J.FT8+2RM5%1TO3L6LSRK06-D$5H/VH+NKY KET0%7R2UN.ICXZA6-A+B1Q37HMTERQHVCKGADFP8I7TASF:2LB114QL1C7W9QH2I:LAVIW7A+MD+LAAZPSHR+A2IS2K*SCK0ZL9AU7MBCMEKVVWFNQY0DRJN*N4C3Z9POGMP1KKVFJ8S53R8%NG908DMV3U370S0RL0"""

    try:
        # Decodificar tudo de uma vez
        zlib_data = base45.b45decode(qr_data)
        json_data = zlib.decompress(zlib_data).decode('utf-8')
        json_obj = json.loads(json_data)

        print("=== JSON DECODIFICADO ===")
        print(json.dumps(json_obj, indent=2, ensure_ascii=False))

    except Exception as e:
        print(f"Erro: {e}")


if __name__ == "__main__":
    # Escolha qual função executar:

    # Para análise completa:
    main()

    # Para ver apenas o JSON final:
    # quick_test()