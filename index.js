// HENRIQUE ALMEIDA FLORENTINO - PESQUISAS 



const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();


// ADICIONADO: dependências mínimas para proteção
const helmet = require('helmet');                 // para CSP/headers de segurança
const { JSDOM } = require('jsdom');               // DOM virtual para DOMPurify no servidor
const createDOMPurify = require('dompurify');     // sanitização de HTML (evita XSS)

// CONFIGURAÇÃO RÁPIDA DO DOMPurify 
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);


const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão
// ALTERAÇÃO: httpOnly foi alterado para true para impedir acesso via JavaScript

app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        // Antes: httpOnly: false (vulnerável)
        // Agora: httpOnly: true, secure em produção, sameSite para mitigar CSRF
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'Strict'
        });
    }
    next();
});

// ADICIONADO: usar Helmet para Content Security Policy
//  Mantendo simples e restritivo: scripts só do próprio domínio 
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],     // bloqueia scripts injetados de outras origens
      objectSrc: ["'none'"],
      imgSrc: ["'self'", "data:"],
      upgradeInsecureRequests: []
    }
  })
);



// Rota principal
app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        res.render('comments', { comments: rows });
    });
});

// Rota para enviar comentários (VULNERÁVEL a XSS 🚨)
// ALTERAÇÃO: sanitizado o conteúdo recebido com DOMPurify antes de salvar

app.post('/comment', (req, res) => {
    const { content } = req.body;

    // Sanitização server-side: remove <script> e atributos perigosos
    // Permitimos apenas algumas tags básicas (ajuste conforme necessidade)
    const clean = DOMPurify.sanitize(content || '', {
      ALLOWED_TAGS: ['b','i','em','strong','a','p','br','ul','ol','li'],
      ALLOWED_ATTR: ['href','title']
    });

    db.run("INSERT INTO comments (content) VALUES (?)", [clean], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});