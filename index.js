// index.js - versão segura com as 4 soluções aplicadas
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const path = require('path');

const app = express();

// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Segurança: Helmet + CSP
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], // bloqueia scripts inline e externos não autorizados
      styleSrc: ["'self'", "'unsafe-inline'"], // cuidado com inline styles
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
    },
  })
);

// Parsing e cookies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Banco em memória
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
  db.run("INSERT INTO comments (content) VALUES (?)", ['Bem-vindo ao desafio de XSS!']);
});

// Middleware para cookies seguros
app.use((req, res, next) => {
  if (!req.cookies.session_id) {
    const sid = 'sid_' + Date.now() + '_' + Math.floor(Math.random() * 100000);
    res.cookie('session_id', sid, {
      httpOnly: true, // Bloqueia acesso via JS
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production', // true em HTTPS
      maxAge: 1000 * 60 * 60 * 24 * 7
    });
  }
  next();
});

// Função de sanitização
function sanitizeUserHtml(input) {
  return sanitizeHtml(input, {
    allowedTags: ['b','i','em','strong','a','p','ul','ol','li','br'],
    allowedAttributes: { 'a': ['href', 'rel', 'target'] },
    transformTags: {
      'a': sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' })
    }
  });
}

// Rota principal
app.get('/', (req, res) => {
  db.all("SELECT * FROM comments ORDER BY id DESC", [], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Erro ao carregar comentários');
    }
    res.render('comments', { comments: rows });
  });
});

// Rota POST /comment
app.post('/comment', (req, res) => {
  const raw = (req.body.content || '').toString();
  const safe = sanitizeUserHtml(raw);

  db.run("INSERT INTO comments (content) VALUES (?)", [safe], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Erro ao salvar comentário');
    }
    res.redirect('/');
  });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
