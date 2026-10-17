# Níveis de severidade usados no relatório
ALTO = "ALTO"
MEDIO = "MÉDIO"
BAIXO = "BAIXO"
INFO = "INFO"

# HSTS com menos de 180 dias é considerado fraco
HSTS_MIN_MAX_AGE = 15552000

# Cabeçalhos de segurança que esperamos encontrar na resposta
SECURITY_HEADERS = {
    "content-security-policy": {
        "nome": "Content-Security-Policy",
        "severidade": ALTO,
        "risco": "Sem CSP, o navegador executa qualquer script injetado na página, facilitando ataques XSS.",
        "recomendacao": "Defina uma política restritiva, por exemplo: default-src 'self'.",
    },
    "x-frame-options": {
        "nome": "X-Frame-Options",
        "severidade": MEDIO,
        "risco": "A página pode ser carregada dentro de um iframe em outro site, permitindo clickjacking.",
        "recomendacao": "Use X-Frame-Options: DENY (ou SAMEORIGIN), ou frame-ancestors no CSP.",
    },
    "x-content-type-options": {
        "nome": "X-Content-Type-Options",
        "severidade": BAIXO,
        "risco": "O navegador pode 'adivinhar' o tipo do arquivo (MIME sniffing) e executar conteúdo como script.",
        "recomendacao": "Use X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "nome": "Referrer-Policy",
        "severidade": BAIXO,
        "risco": "A URL completa (que pode conter dados sensíveis) pode vazar para outros sites pelo Referer.",
        "recomendacao": "Use Referrer-Policy: strict-origin-when-cross-origin (ou no-referrer).",
    },
    "permissions-policy": {
        "nome": "Permissions-Policy",
        "severidade": BAIXO,
        "risco": "Não há restrição de acesso a recursos do navegador (câmera, microfone, localização...).",
        "recomendacao": "Desative o que não for usado, por exemplo: camera=(), microphone=(), geolocation=().",
    },
}

# Cabeçalhos que revelam tecnologia/versão do servidor
INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def _finding(severidade: str, cabecalho: str, mensagem: str, recomendacao: str = "") -> dict:
    return {
        "severidade": severidade,
        "cabecalho": cabecalho,
        "mensagem": mensagem,
        "recomendacao": recomendacao,
    }


def _check_hsts(headers: dict, url: str) -> list[dict]:
    """Verifica o Strict-Transport-Security, que só faz sentido em HTTPS."""
    if not url.startswith("https://"):
        return [_finding(
            ALTO, "HTTPS",
            "O site respondeu via HTTP sem criptografia; os dados trafegam em texto puro.",
            "Sirva o site por HTTPS e redirecione todo o tráfego HTTP para HTTPS.",
        )]

    value = headers.get("strict-transport-security")
    if value is None:
        return [_finding(
            MEDIO, "Strict-Transport-Security",
            "Ausente. O navegador pode ser forçado a usar HTTP (ataque de downgrade/SSL stripping).",
            "Use Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )]

    # Extrai o valor de max-age da diretiva
    max_age = None
    for directive in value.split(";"):
        directive = directive.strip().lower()
        if directive.startswith("max-age="):
            try:
                max_age = int(directive.split("=", 1)[1].strip('"'))
            except ValueError:
                pass

    if max_age is None or max_age < HSTS_MIN_MAX_AGE:
        return [_finding(
            BAIXO, "Strict-Transport-Security",
            f"Presente, mas com max-age baixo ou inválido ({value}).",
            "Use max-age de pelo menos 15552000 (180 dias), idealmente 31536000 (1 ano).",
        )]
    return []


def _check_cookies(cookies: list[str], url: str) -> list[dict]:
    """Verifica as flags de segurança de cada cabeçalho Set-Cookie."""
    findings = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        # Flags vêm depois do primeiro ";" (ex.: "id=abc; Secure; HttpOnly")
        flags = [part.strip().split("=")[0].lower() for part in cookie.split(";")[1:]]

        missing = []
        if url.startswith("https://") and "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")

        if missing:
            findings.append(_finding(
                BAIXO, "Set-Cookie",
                f"Cookie '{name}' sem as flags: {', '.join(missing)}.",
                "Secure impede envio por HTTP, HttpOnly bloqueia acesso via JavaScript e SameSite reduz CSRF.",
            ))
    return findings


def analyze_headers(headers: dict, url: str, cookies: list[str] | None = None) -> list[dict]:
    """
    Analisa os cabeçalhos HTTP da resposta e retorna uma lista de achados,
    cada um com severidade, cabeçalho, mensagem e recomendação.
    `cookies` é a lista de valores brutos de Set-Cookie.
    """
    # Nomes de cabeçalho não diferenciam maiúsculas/minúsculas
    headers = {name.lower(): value for name, value in headers.items()}
    findings = []

    findings += _check_hsts(headers, url)

    for key, info in SECURITY_HEADERS.items():
        # frame-ancestors no CSP substitui o X-Frame-Options
        if key == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            continue
        if key not in headers:
            findings.append(_finding(info["severidade"], info["nome"], f"Ausente. {info['risco']}", info["recomendacao"]))

    if headers.get("x-content-type-options", "nosniff").lower() != "nosniff":
        findings.append(_finding(
            BAIXO, "X-Content-Type-Options",
            f"Valor inválido: '{headers['x-content-type-options']}'.",
            "O único valor válido é nosniff.",
        ))

    for key in INFO_LEAK_HEADERS:
        if key in headers:
            findings.append(_finding(
                INFO, key.title(),
                f"Revela informação do servidor: '{headers[key]}'.",
                "Remova ou generalize esse cabeçalho para não facilitar a busca por vulnerabilidades conhecidas.",
            ))

    findings += _check_cookies(cookies or [], url)

    order = [ALTO, MEDIO, BAIXO, INFO]
    return sorted(findings, key=lambda f: order.index(f["severidade"]))
