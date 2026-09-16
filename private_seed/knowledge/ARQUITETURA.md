# ARQUITETURA
A Efatá atua como plano de inteligência e governança.
A Vertical Legal mantém frontend, backend, banco, storage, migrations, deploy e domínio próprios.
A integração ocorre por contratos versionados, APIs/M2M/eventos. Não existe acesso direto entre os bancos.

O Judicial Integration Hub é a camada prevista para adapters judiciais. O eproc deverá entrar como fonte oficial
por EprocAdapter READ-ONLY. Credenciais ficam no backend e nunca no navegador.

Regras: tenant/case isolation, armazenamento privado, auditabilidade, human review e external_write=false nesta etapa.
