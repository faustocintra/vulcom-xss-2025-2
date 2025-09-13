const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');             // CORREÇÃO aplicada (import)
const sanitizeHtml = require('sanitize-html'); // CORREÇÃO aplicada (import)
const app = express();

// CORREÇÃO: importar helmet e sanitize-html
// const helmet = require('helmet');
// const sanitizeHtml = require('sanitize-html');

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// CORREÇÃO: usar helmet e CSP
/*
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  next();
});
*/

// CORREÇÃO aplicada: ativando helmet e adicionando CSP
app.use(helmet());
app.use((req, res, next) => {
  // CSP simples — bloqueia scripts externos/inline; ajuste conforme necessidade
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"
  );
  next();
});

db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        // CORREÇÃO: trocar httpOnly:false por httpOnly:true, e adicionar secure + sameSite
        // original (vulnerável): res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: false });
        const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', {
          httpOnly: true,    // CORREÇÃO aplicada
          secure: isSecure,  // CORREÇÃO aplicada
          sameSite: 'Strict' // CORREÇÃO aplicada
        });
    }
    next();
});

app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) return res.send('Erro ao carregar comentários');
        res.render('comments', { comments: rows });
    });
});

app.post('/comment', (req, res) => {
    const { content } = req.body;

    // CORREÇÃO: validar e sanitizar entrada antes de salvar
    // const clean = sanitizeHtml(content, { allowedTags: [] });

    // Validação básica
    if (typeof content !== 'string' || content.trim().length === 0) {
      return res.status(400).send('Comentário inválido');
    }
    if (content.length > 2000) {
      return res.status(400).send('Comentário muito longo');
    }

    // Sanitização aplicada (remove <script>, atributos on*, src de scripts, etc.)
    const clean = sanitizeHtml(content, {
      allowedTags: ['b','i','em','strong','a','p','br','ul','ol','li'],
      allowedAttributes: {
        a: ['href', 'rel', 'target']
      },
      transformTags: {
        'a': sanitizeHtml.simpleTransform('a', { rel: 'nofollow', target: '_blank' })
      }
    });

    // Salva o conteúdo sanitizado (substitui content por clean)
    db.run("INSERT INTO comments (content) VALUES (?)", [clean], (err) => {
        if (err) return res.send('Erro ao salvar comentário');
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
