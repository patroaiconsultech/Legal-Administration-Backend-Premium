# Efatá Secure Briefing Portal — Backend V1.1

Backend independente do briefing confidencial do Projeto Estevez Guarda.

## Decisão arquitetural

Este portal **não altera o core EFATÁ**. A baseline EFATÁ B1 fornecida em 16/09/2026 é usada como
referência read-only para posicionamento dos agentes e futuros contratos de integração.

Referências físicas:

- EFATÁ Frontend B1 SHA-256: `eee29f01c3930ab2198a03be6c7e6b2d3313114020b03f596ed6e6f9c30f41b0`
- EFATÁ Backend B1 SHA-256: `d92034e9d80d404d96c66afa61517d6cc571da81aa45472799d238a330121ca5`

## Fluxo V1.1

```text
solicitação pública
→ PENDING_ADMIN_APPROVAL
→ Super Admin recebe painel + push/e-mail
→ APPROVE / REJECT
→ se aprovado: magic link individual
→ sessão temporária
→ termo de confidencialidade
→ aceite
→ conteúdo confidencial
→ Hyper Agente opcional
```

Não existe OTP para o visitante no modo canônico `ACCESS_APPROVAL_MODE=superadmin`.
As rotas legadas `/api/auth/request-otp` e `/api/auth/verify-otp` retornam 404 nesse modo.
A conta administrativa permanece protegida por senha + OTP via Resend.

## Implementado

- AccessRequest persistido;
- decisão humana do Super Admin;
- magic link one-time após aprovação;
- Termo v1.0 + SHA-256;
- aceite jurídico e recibo;
- audit trail;
- private storage;
- PWA Web Push opcional;
- Resend;
- agent catalog baseado na EFATÁ B1;
- Hyper Agente atrás de feature flag;
- produção fail-closed.

## Hyper Agente

`AGENT_ENABLED=false` por padrão.

A base curada inclui o catálogo organizacional da EFATÁ B1. O catálogo fonte está em
`PROPOSAL_ONLY` e declara que `registered != configured != ready`. O agente não pode transformar
identidade organizacional em readiness não comprovada.

## Desenvolvimento

```bash
cp .env.example .env
python -m app.cli hash-password "uma-senha-forte"
pip install -r requirements.txt
alembic upgrade head
python -m app.seed
uvicorn app.main:app --reload
```

## Web Push

Gere o par VAPID uma única vez:

```bash
python scripts/generate_vapid_keys.py
```

Salve as três saídas exclusivamente como secrets no Railway e ative:

```text
PUSH_ENABLED=true
```

Rotacionar o VAPID invalida subscriptions existentes.
