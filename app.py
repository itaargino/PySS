from scanner.input_handler import get_url_from_user
from scanner.fetcher import fetch_url
from scanner.header_analyzer import analyze_headers

def main():
    """
    Ponto de entrada principal do programa.
    Pede uma URL ao usuário, busca os dados e exibe um resumo.
    """
    try:
        url = get_url_from_user()
    except ValueError as e:
        print(f"[ERRO] {e}")
        return

    result = fetch_url(url)

    if result is None:
        print(f"Falha ao obter dados da URL: {url}")
        return
    
    print("\n=== Resultado Inicial ===")
    print(f"URL Analisada: {url}")
    if result['url'] != url:
        print(f"Redirecionada para: {result['url']}")
    print(f"Status da Resposta: {result['status_code']}")
    print(f"Quantidade de Cabeçalhos: {len(result['headers'])}")

    findings = analyze_headers(result['headers'], result['url'], result['cookies'])
    print_header_report(findings)
    print("\n========================")


def print_header_report(findings: list[dict]):
    """Exibe os achados da análise de cabeçalhos, do mais grave ao menos grave."""
    print("\n=== Análise de Cabeçalhos de Segurança ===")
    if not findings:
        print("Nenhum problema encontrado nos cabeçalhos.")
        return

    for f in findings:
        print(f"\n[{f['severidade']}] {f['cabecalho']}")
        print(f"  {f['mensagem']}")
        if f['recomendacao']:
            print(f"  Recomendação: {f['recomendacao']}")

    # Resumo com a contagem por severidade
    counts = {}
    for f in findings:
        counts[f['severidade']] = counts.get(f['severidade'], 0) + 1
    summary = ", ".join(f"{sev}: {n}" for sev, n in counts.items())
    print(f"\nTotal de achados: {len(findings)} ({summary})")


if __name__ == "__main__":
    main()
