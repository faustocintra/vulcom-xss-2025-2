// Vulnerabilidades mitigadas com DOMPurify, Helmet (CSP) e escape HTML
// 1. A aplicação agora utiliza DOMPurify para sanitizar o conteúdo dos comentários antes de armazená-los no banco de dados, prevenindo ataques XSS.
// 2. A biblioteca Helmet foi adicionada para configurar políticas de segurança de conteúdo (CSP), ajudando a mitigar ataques XSS ao restringir as fontes de scripts.
// 3. O cookie de sessão foi configurado com a flag HttpOnly, impedindo que scripts do lado do cliente acessem o cookie, mitigando o risco de roubo de sessão via XSS.
// 4. A renderização dos comentários na página utiliza EJS, que escapa automaticamente o conteúdo, prevenindo a injeção de HTML malicioso.

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();

// importando helmet para segurança CSP
const helmet = require('helmet');
app.use(helmet());

// utilizando DOMpurify para sanitização de entradas
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

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
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: true }); // VULNERÁVEL A XSS 🚨(resolvido com httpOnly: true)
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
    
    // SANITIZAÇÃO ACONTECENDO AQUI!
    // A variável 'cleanContent' conterá o HTML seguro.
    const cleanContent = DOMPurify.sanitize(content);

    db.run("INSERT INTO comments (content) VALUES (?)", [cleanContent], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
