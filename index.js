// Mitigações XSS aplicadas (resumo):


// 1. Sanitização de entrada com DOMPurify (server-side):
// - Ao receber o comentário, o código usa `DOMPurify.sanitize(...)` para remover/normalizar
// conteúdo perigoso. Foi definida uma whitelist de tags (ALLOWED_TAGS) e atributos
// permitidos (ALLOWED_ATTR).

// 2. Validações adicionais no servidor:
// - Limite de tamanho (350 caracteres) para reduzir superfície de ataque.
// - Verificação de comentário vazio (trim).

// 3. Cookies seguros/HTTP-only:
// - O cookie `session_id` é enviado com `httpOnly: true` (impede acesso via JavaScript no cliente).
// - `sameSite: 'strict'` para evitar ataques CSRF.

// 4. Uso de consultas parametrizadas na inserção SQL:
// - `db.run("INSERT INTO comments (content) VALUES (?)", [sanitizedContent])` evita SQL Injection.

// 5. No EJS (front-end) utilizei o escape automático: <%= comment.content %> para evitar ataques XSS e limitei a quantidade de caracteres.

// 6. Content Security Policy (CSP):
// - Uso do Helmet para configurar a CSP. Isso impede que scripts injetados
//   (inline ou externos não autorizados) sejam executados pelo navegador.

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();
const helmet = require('helmet');

const createDOMPurify = require('dompurify'); // Importa o DOMPurify
const { JSDOM } = require('jsdom'); // Importa o JSDOM

const window = new JSDOM('').window; // Cria um objeto window com o DOM vazio
const DOMPurify = createDOMPurify(window); // DOMPurify para purificar o HTML e evitar ataques XSS


const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Configuração do Helmet com CSP
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"], // só permite conteúdo do mesmo domínio
      scriptSrc: ["'self'"], // só scripts locais, bloqueia inline e externos
      objectSrc: ["'none'"], // bloqueia Flash, Silverlight etc
      upgradeInsecureRequests: [], // força HTTPS se disponível
    },
  })
);

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { 
            httpOnly: true, 
            secure: false /* em produção, secure: true */,
            sameSite: 'strict' // serve para evitar ataques CSRF
        });
    }
    next();
});

// Rota principal
app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        res.render('comments', { comments: rows });
    });
});

app.post('/comment', (req, res) => {
    const { content } = req.body;

    if(content.length > 350) {
        return res.send('Comentário muito longo, limite de 350 caracteres').statusCode(400);
    }

    if(!content || content.trim() === '') {
        return res.send('Comentário vazio, por favor preencha-o').statusCode(400);
    }

    // Sanitização do comentário usando DOMPurify
    // Somente tags que estiverem na whitelist serão permitidas (tags de formatação no geral)
    const sanitizedContent = DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'br', 'p', 'ul', 'ol', 'li'],
        ALLOWED_ATTR: []
    });
    console.log(sanitizedContent)


    db.run("INSERT INTO comments (content) VALUES (?)", [sanitizedContent], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
