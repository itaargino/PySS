from scanner.input_handler import get_url_from_user
from scanner.fetcher import fetch_url

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
    print(f"Status da Resposta: {result['status_code']}")
    print(f"Quantidade de Cabeçalhos: {len(result['headers'])}")
    print("\nPrimeiros 200 caracteres do HTML:")
    print(result['html'][:200])
    print("...")
    print("\n========================")
if __name__ == "__main__":
    main()
