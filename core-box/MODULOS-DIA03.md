# Core Box — módulos do Dia 03

Esta versão do Core Box (em "produção", continuidade dos Dias 01 e 02) ganhou dois
módulos novos, que são os ALVOS do teste de segurança do Dia 03.

## BoxGPT — assistente virtual  (`/assistente`)
Assistente que conversa com o cliente autenticado e consulta dados da conta para ajudar.
- `GET  /assistente`                      interface de chat
- `POST /assistente/api/mensagem`         envia {texto}, recebe a resposta
- `GET  /assistente/api/conversas/<id>`   recupera uma conversa
- `GET  /assistente/api/historico`        histórico da conversa atual

## SSO — login federado (OpenID Connect)  (`/sso`)
- `GET      /sso/login`         inicia o fluxo e mostra a requisição de autorização
- `GET      /sso/callback`      recebe o id_token do IdP e autentica
- `GET/POST /sso/inspecionar`   inspetor de token (decodifica header e payload)

Tokens de exemplo para análise: pasta `../lab-sso/`.

> AVISO: módulos intencionalmente vulneráveis, para treino (Dia 03). Dados fictícios.
> Use apenas no ambiente autorizado do curso. Trate o BoxGPT como caixa-preta:
> a entrega é a evidência da interação, não a leitura do código.
