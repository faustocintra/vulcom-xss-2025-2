const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const sanitizeHtml = require('sanitize-html');
const helmet = require('helmet');
const app = express();

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet()); // Adiciona cabeçalhos de segurança
app.set('view engine', 'ejs');

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: false }); // VULNERÁVEL A XSS 🚨
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
    let { content } = req.body;
    // Validar tipo e tamanho da entrada
    if (typeof content !== 'string' || content.length > 500) {
        return res.send('Comentário inválido.');
    }
    // Permitir apenas caracteres alfanuméricos e pontuação básica
    const regex = /^[\w\s.,!?@#\$%&*()\-+=:;\/'"áéíóúãõâêîôûçÁÉÍÓÚÃÕÂÊÎÔÛÇ]+$/i;
    if (!regex.test(content)) {
        return res.send('Comentário contém caracteres não permitidos.');
    }
    // Sanitizar entrada do usuário
    content = sanitizeHtml(content, {
        allowedTags: [], // Remove todas as tags HTML
        allowedAttributes: {}
    });
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
