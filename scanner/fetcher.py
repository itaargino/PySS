import requests
def fetch_url(url: str) -> dict | None:
    """
    Faz uma requisição GET para a URL, tratando erros comuns.
    Retorna um dicionário com dados da resposta ou None em caso de falha.
    """
    try:
        # Define um cabeçalho User-Agent para simular um navegador real
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, timeout=10, allow_redirects=True, headers=headers)
        response.raise_for_status()  # Lança HTTPError para status de erro (4xx ou 5xx)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "html": response.text
        }
    # Captura exceções da biblioteca requests (ConnectionError, Timeout, etc.)
    except requests.exceptions.ConnectionError:
        print(f"[ERRO] Não foi possível conectar à URL '{url}'. Verifique o nome do domínio e sua conexão com a internet.")
        return None
    except requests.exceptions.Timeout:
        print(f"[ERRO] A requisição para '{url}' demorou muito para responder (timeout).")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[ERRO] A URL '{url}' retornou um status de erro: {e.response.status_code} {e.response.reason}.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERRO] Falha na requisição para {url}. Causa: {e}")
        return None
    # Captura qualquer outra exceção não prevista para evitar que o programa quebre
    except Exception as e:
        print(f"[ERRO] Ocorreu um erro inesperado: {e}")
        return None