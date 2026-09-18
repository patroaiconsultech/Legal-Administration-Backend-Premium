# Estevez Guarda MVP 1

O backend mantém a autenticação/session/admin já existente e acrescenta conteúdo funcional do MVP.

Mudanças:
- presentation version `2026-09-18.mvp1`;
- KB pública demonstrativa com Grupo Construmil, Móveis Schoffen e S&D Transportes;
- Assistente Estevez orientado a operações/documentos;
- health service label Estevez;
- nenhum schema/migration novo.

Railway:
AGENT_ENABLED=true
AGENT_PROVIDER=openai
AGENT_MODEL=gpt-5.6-luna
OPENAI_API_KEY=<secret>
AGENT_STORE_CONTENT=false
SEED_CONTENT_ON_STARTUP=true
