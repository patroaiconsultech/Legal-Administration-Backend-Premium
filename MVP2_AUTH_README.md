# Estevez Guarda MVP2 — conta recorrente

Nova migration:
`003_portal_accounts`

Fluxo:
1. solicitação pública;
2. Super Admin aprova;
3. e-mail com link `/activate/<token>`;
4. abertura do link envia OTP de ativação;
5. OTP válido + senha criam `PortalAccount`;
6. acessos seguintes usam `/api/account/login` com e-mail + senha.

A autenticação administrativa permanece senha + OTP.

Importante para o deploy atual com frontend/backend em origens Railway diferentes:
- o frontend conserva o CSRF devolvido pelo backend;
- cookies de sessão do portal usam `SameSite=None` quando `COOKIE_SECURE=true`.
