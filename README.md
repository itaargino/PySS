## PySS — Python Simple Security Scanner

PySS é um scanner simples de segurança para websites.
Ele recebe uma URL como entrada, realiza verificações básicas de segurança e retorna um relatório claro sobre possíveis riscos encontrados.

### Funcionalidades (no momento)
- Validação de URL
- Interpretação de erros da requisição (conexão, timeout, status 4xx/5xx)
- Análise de cabeçalhos de segurança, com severidade (ALTO, MÉDIO, BAIXO, INFO) e recomendação:
  - HTTPS e `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
  - Vazamento de informação (`Server`, `X-Powered-By`, ...)
  - Flags de cookies (`Secure`, `HttpOnly`, `SameSite`)

### Como usar
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
