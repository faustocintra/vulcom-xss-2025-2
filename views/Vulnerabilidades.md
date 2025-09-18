Vulnerabilidades: 
Stored XSS: A rota /comment aceita um content do usuário e o salva diretamente no banco de dados sem nenhuma validação ou sanitização.

Renderização Insegura: A rota principal (/) busca esses comentários e os renderiza na página usando <%- comment.content %>. A tag <%- %> no EJS renderiza o conteúdo sem escapar caracteres HTML. Isso permite que um atacante que insira <script>alert('XSS')</script> como um comentário execute JavaScript no navegador de qualquer usuário que visite a página.

Roubo de Cookie: O cookie session_id é criado com httpOnly: false. Isso o torna acessível via JavaScript (document.cookie), permitindo que o script malicioso do atacante leia o cookie e o envie para um servidor externo.

Como Rescolver: 

Trocar <%- %> por <%= %> (escape de saída, já resolve muita coisa).
Sanitizar a entrada com sanitize-html (limpa os dados antes de salvar).
Configurar Content Security Policy com Helmet (bloqueia execução de scripts injetados).
Definir HttpOnly e Secure nos cookies (impede roubo em caso de falha).
Proteger o Cookie com a Flag HttpOnly
Esta medida não previne o XSS, mas mitiga drasticamente seu impacto, impedindo que o ataque mais comum (roubo de sessão) seja bem-sucedido.

O que faz?: Define a flag HttpOnly no cookie. Isso instrui o navegador a não permitir que o cookie seja acessado por scripts do lado do cliente.
Como implementar?: Altere a opção httpOnly para true na criação do cookie.
Esta é uma abordagem proativa. Em vez de apenas escapar na saída, nós limpamos a entrada antes mesmo de salvá-la no banco de dados. Isso é uma ótima prática de "defesa em profundidade". Usaremos uma biblioteca popular e robusta chamada sanitize-html.

Primeiro, instale a biblioteca:
npm install sanitize-html

O que faz?: Remove todas as tags HTML e atributos perigosos (como onclick ou <script>) da entrada do usuário, permitindo opcionalmente algumas tags seguras (como <b> ou <i>, se desejado).
Como implementar?: No seu arquivo app.js, importe a biblioteca e aplique-a na rota /comment.

mplementar uma Política de Segurança de Conteúdo (CSP)
CSP é uma camada de segurança extra que instrui o navegador a carregar recursos (scripts, estilos, etc.) apenas de fontes confiáveis, ajudando a mitigar ataques XSS.

O que faz?: Adiciona um cabeçalho HTTP Content-Security-Policy à resposta. Podemos definir uma política que, por exemplo, proíbe a execução de scripts inline.
Como implementar?: Usaremos a biblioteca helmet, que facilita a configuração de vários cabeçalhos de segurança, incluindo o CSP.

