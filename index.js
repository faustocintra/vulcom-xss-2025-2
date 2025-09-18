const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser'); 
const helmet = require('helmet'); // helmet adiciona vários headers HTTP de segurança automaticamente
const sanitizeHtml = require('sanitize-html'); // Biblioteca que remove/filtra tags e atributos perigososs em HTML fornecido por usuários.
const crypto=require('crypto'); //Módulo nativo do Node.js para operações criptográficas (gerar IDs)
const app = express();

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(helmet()); //Ativa o helmet com as configurações padrão (vários headers de proteção)

// CSP: bloqueia scripts externos e inline 
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"], // permitir apenas scripts do mesmo origin
    connectSrc: ["'self'"],
    imgSrc: ["'self'","data:"],
    styleSrc: ["'self'", "'unsafe-inline'"], 
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}));


// Criar tabela de comentários
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão seguro
app.use((req, res, next) => {
  if (!req.cookies.session_id) {
    // Gere um id de sessão aleatório e *não* coloque flags ou segredos na cookie
    const sessionId = crypto.randomBytes(16).toString('hex');
    res.cookie('session_id', sessionId, {
      httpOnly: true, // impede acesso via document.cookie
      secure: process.env.NODE_ENV === 'production', 
      sameSite: 'Lax' 
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

// Rota para enviar comentários (validação + sanitização)
app.post('/comment', (req, res) => {
  let { content } = req.body;
  if (typeof content !== 'string') {
    return res.status(400).send('Conteúdo inválido');
  }
  // validações básicas
  if (content.length === 0 || content.length > 2000) {
    return res.status(400).send('Comentário vazio ou muito grande (max 2000 caracteres)');
  }
  //Aceitação de um subconjunto seguro de tags
  const safe = sanitizeHtml(content, { //sanitize remove atributos perigosos e tags
    allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    allowedAttributes: {
      'a': ['href', 'rel', 'target']
    },
    transformTags: {
      'a': (tagName, attribs) => {
        return {
          tagName: 'a',
          attribs: {
            href: attribs.href || '#',
            rel: 'noopener noreferrer',
            target: '_blank'
          }
        };
      }
    }
  });
  //Insere conteúdo sanitizado na tabela para prevenir SQL injection 
    db.run("INSERT INTO comments (content) VALUES (?)", [safe], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Erro ao salvar comentário');
    }
    res.redirect('/');
  });
});


app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
