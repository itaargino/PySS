from validator_collection import validators, checkers
from validator_collection.errors import InvalidURLError


def normalize_url(url: str) -> str:
    url = url.strip()

    # Se não tiver http/https, adiciona https por padrão
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def is_valid_url(url: str) -> bool:
    """Retorna True se a URL for válida segundo validator-collection."""
    return checkers.is_url(url)


def get_url_from_user(allow_special_ips: bool = False) -> str:
    url = input("Digite a URL para análise: ").strip()
    url = normalize_url(url)

    try:
        # validators.url normaliza e valida profundamente
        url = validators.url(url, allow_special_ips=allow_special_ips)
        return url

    except InvalidURLError:
        raise ValueError(f"URL inválida: {url}")
