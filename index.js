const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
// CORREÇÃO 1: Importando bibliotecas para sanitização HTML
const { JSDOM } = require('jsdom');        // Simula um DOM no servidor
const createDOMPurify = require('dompurify'); // Sanitiza HTML removendo código malicioso

const app = express();

// CORREÇÃO 2: Configurando DOMPurify para funcionar no servidor Node.js
// DOMPurify normalmente funciona no browser, precisamos simular um DOM
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// CORREÇÃO 3: Content Security Policy (CSP) - Primeira linha de defesa contra XSS
app.use((req, res, next) => {
    // CSP bloqueia execução de scripts inline e externos não autorizados
    // default-src 'self': Só permite recursos da própria origem
    // script-src 'self': Só permite scripts da própria origem (bloqueia <script> inline)
    // style-src 'self' 'unsafe-inline': Permite CSS da própria origem e inline (para o style no HTML)
    // object-src 'none': Bloqueia plugins como Flash
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';");
    next();
});

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// CORREÇÃO 4: Cookie seguro - Impede roubo da flag via JavaScript
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { 
            httpOnly: true,    // CRÍTICO: Impede acesso via document.cookie (JavaScript)
            secure: false,     // Em produção com HTTPS, deve ser true
            sameSite: 'strict' // Previne ataques CSRF - cookie só enviado em requisições da mesma origem
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

// CORREÇÃO 5: Sanitização e validação completa da entrada do usuário
app.post('/comment', (req, res) => {
    const { content } = req.body;
    
    // VALIDAÇÃO 1: Verificar se o conteúdo não está vazio
    if (!content || content.trim().length === 0) {
        return res.send('Comentário não pode estar vazio');
    }
    
    // VALIDAÇÃO 2: Limitar tamanho para prevenir ataques de DoS
    if (content.length > 500) {
        return res.send('Comentário muito longo (máximo 500 caracteres)');
    }
    
    // CORREÇÃO PRINCIPAL: Sanitização usando DOMPurify
    // Remove TODAS as tags perigosas como <script>, <iframe>, <object>, etc.
    // Mantém apenas tags de formatação básica e seguras
    const sanitizedContent = DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'], // Só permite formatação básica
        ALLOWED_ATTR: []  // Remove TODOS os atributos (onclick, onload, href, etc.)
    });
    
    // Salva o conteúdo já sanitizado no banco
    db.run("INSERT INTO comments (content) VALUES (?)", [sanitizedContent], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});