const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('isomorphic-dompurify');

const app = express();
const db = new sqlite3.Database(':memory:');

// Configura DOMPurify
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Configura Content Security Policy (CSP)
app.use(
    helmet.contentSecurityPolicy({
        useDefaults: true,
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"], // Bloqueia scripts externos e inline
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        },
    })
);

// Criar tabela de comentários segura
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão (agora protegido com HttpOnly)
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: true }); // Agora protegido
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

// Rota para enviar comentários (agora sanitizando entrada)
app.post('/comment', (req, res) => {
    let { content } = req.body;

    // Sanitiza o conteúdo antes de salvar
    content = DOMPurify.sanitize(content);

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
