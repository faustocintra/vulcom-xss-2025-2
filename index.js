const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();
const { JSDOM } = require("jsdom");
const createDOMPurify = require("dompurify");
const { EMPTY } = require('sqlite3');

const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Implementação de Content Security Policy (CSP) para bloquear execução de scripts injetados
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "frame-src 'none'; " +
        "object-src 'none';"
    );
    next();
});

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão com flag HttpOnly para impedir acesso via JavaScript
app.use((req, res, next) => {
    if (!req.cookies.session_id) { // Definindo para o token não ser exibido!
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', {
            httpOnly: true, // Flag HttpOnly implementada para prevenir acesso via JavaScript
            secure: false,
            sameSite: 'Strict'
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

// Rota para enviar comentários - CORRIGIDA com sanitização de entrada
app.post('/comment', (req, res) => {
    const { content } = req.body;
    console.log(content);
    const comentarioPurificado = DOMPurify.sanitize(content); // Sanitização da entrada usando DOMPurify para remover scripts maliciosos
    console.log(typeof(comentarioPurificado))
    console.log("Comentário purificado:", comentarioPurificado)
    db.run("INSERT INTO comments (content) VALUES (?)", [comentarioPurificado], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
