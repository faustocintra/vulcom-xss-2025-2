// Luiz Felipe Vieira Soares
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const crypto = require('crypto');
const app = express();

const db = new sqlite3.Database(':memory:');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

db.serialize(() => {
  db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
  db.run("INSERT INTO comments (content) VALUES (?)", ['Bem-vindo ao desafio de XSS!']);
});

app.use(helmet()); 
// Middleware pra gerar nonce por requisição e aplicar CSP usando esse nonce
app.use((req, res, next) => {
  // Gera um nonce base64 por requisição
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce; // disponível no template EJS

  // CSP que permite apenas scripts com nonce gerado, bloqueia inline sem nonce e scripts externos
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`, 
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "style-src 'self' 'unsafe-inline'", 
  ].join('; ');

  res.setHeader('Content-Security-Policy', csp);
  next();
});

// --- Cookie de sessão seguro (HttpOnly, Secure, SameSite) ---
app.use((req, res, next) => {
  if (!req.cookies.session_id) {
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
    res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', {
      httpOnly: true,    
      secure: isSecure,  
      sameSite: 'Strict'
    });
  }
  next();
});

// --- Página principal: mostra comentários (saída ESCAPED em EJS) ---
app.get('/', (req, res) => {
  db.all("SELECT * FROM comments ORDER BY id DESC", [], (err, rows) => {
    if (err) return res.status(500).send('Erro ao carregar comentários');
    res.render('comments', { comments: rows }); 
  });
});

// --- Rota para postar comentário: valida + sanitize antes de salvar ---
app.post('/comment', (req, res) => {
  const { content } = req.body;

  if (typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).send('Comentário inválido');
  }
  if (content.length > 2000) {
    return res.status(400).send('Comentário muito longo');
  }

  // Sanitização: permite apenas algumas tags seguras
  const clean = sanitizeHtml(content, {
    allowedTags: ['b','i','em','strong','a','p','br','ul','ol','li'],
    allowedAttributes: {
      a: ['href', 'rel', 'target']
    },
    transformTags: {
      'a': sanitizeHtml.simpleTransform('a', { rel: 'nofollow', target: '_blank' })
    }
  });

  db.run("INSERT INTO comments (content) VALUES (?)", [clean], (err) => {
    if (err) return res.status(500).send('Erro ao salvar comentário');
    res.redirect('/');
  });
});

app.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
});
