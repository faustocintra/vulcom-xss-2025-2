const express = require('express');
const helmet = require('helmet'); // solução de uso de CSP
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();

const db = new sqlite3.Database(':memory:');
app.use(helmet()); // Usando Helmet solução de Uso de Content Security Policy (CSP)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão

//Solução - Definir a Flag HttpOnly nos Cookies
// A flag HttpOnly em um cookie instrui o navegador a nunca
// permitir que aquele cookie seja acessado por JavaScript do lado do
// cliente (document.cookie). Isso impede que um script malicioso roube o
// cookie de sessão e o envie para um invasor.

app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: true }); // trocando o httpOnly para true vai proteger o cookie de ser acessado via JS
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

// Rota para enviar comentários (VULNERÁVEL a XSS 🚨)
app.post('/comment', (req, res) => {
    const { content } = req.body;
    db.run("INSERT INTO comments (content) VALUES (?)", [content], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
