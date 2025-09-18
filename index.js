const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();

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
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: true, secure: true }); // VULNERÁVEL A XSS 🚨

    // 1 - transformar o httponly em true, para impedir acesso via javascript no navegador

    // 2 - colocar secure em true, para permitir apenas conexões https
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

const sanitize = (str) => str.replace(/<[^>]*>?/gm, '');
// função para remover tags HTML do comentário

// Rota para enviar comentários (VULNERÁVEL a XSS 🚨)
app.post('/comment', (req, res) => {
    const { content } = req.body;
    // função
    const safeContent = sanitize(content);
    db.run("INSERT INTO comments (content) VALUES (?)", [safeContent], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
