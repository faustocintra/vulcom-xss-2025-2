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
app.use(helmet());
app.set('view engine', 'ejs');

db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'opaque_session_id_example', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
    }
    next();
});

app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        res.render('comments', { comments: rows });
    });
});

app.post('/comment', (req, res) => {
    const raw = req.body.content || '';
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2000) {
        return res.status(400).send('Comentário inválido');
    }
    const clean = sanitizeHtml(raw, { allowedTags: [], allowedAttributes: {} });
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
