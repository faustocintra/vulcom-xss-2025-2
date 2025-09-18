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
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: false }); // VULNERÁVEL A XSS 🚨
    }
    next();
});
/*
Tornar o cookie inacessível no JavaScript para evitar roubo atraves de XSS
res.cookie('session_id', 'opaque_session_id_example', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
});
*/


// Rota principal
app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        res.render('comments', { comments: rows });
    });
});
/*
garantir que a view escape a saída ao exibir comentários.
em EJS usar "<li><%= c.content %></li>"  (USAR <%= para ESCAPAR),
evitar usar <%- c.content %> pois imprime sem escape.
*/

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

/*
sanitizar o input antes de salvar:
const sanitizeHtml = require('sanitize-html');
const raw = req.body.content || '';
if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2000) {
    return res.status(400).send('Comentario invalido');
}
const clean = sanitizeHtml(raw, { allowedTags: [], allowedAttributes: {} });
db.run("INSERT INTO comments (content) VALUES (?)", [clean], ...);
*/
// --------------------------------------
/*
Validação de tamanho e tipo, evitar payloads enormes:
    "if (typeof content !== 'string' || content.length > 2000)" 
*/

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
