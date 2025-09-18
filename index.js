const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Criar tabela de comentários
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        // CORREÇÃO: Definir a flag HttpOnly como true
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: true }); // CORRIGIDO ✅
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

// Rota para enviar comentários (O backend está seguro contra SQLi, o XSS é corrigido no frontend)
app.post('/comment', (req, res) => {
    const { content } = req.body;
    // O uso de prepared statements (?) já protege contra SQL Injection.
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


// O back-end era responsável por configurar o ambiente e gerenciar os dados, 
// mas sua principal vulnerabilidade estava na forma como configurava o cookie de sessão.

// Ativação da Flag HttpOnly no Cookie de Sessão
// Alteração Realizada: A configuração do cookie de sessão foi modificada de { httpOnly: false } para { httpOnly: true }

// Vulnerabilidade Corrigida: Vazamento de Informações Sensíveis via XSS. 
// Sem a flag HttpOnly, um script malicioso injetado na página (através da vulnerabilidade de XSS do front-end) 
// poderia facilmente roubar o cookie de sessão com o comando document.cookie.

// Impacto da Correção: Com HttpOnly: true, o navegador é instruído a bloquear o acesso ao cookie por parte de qualquer script do lado do cliente. 
// O cookie continua sendo enviado ao servidor a cada requisição, mas fica invisível e inacessível para o JavaScript. 
// Isso funciona como uma camada de defesa crucial, protegendo a sessão do usuário mesmo que uma falha de XSS ocorra em outra parte do sistema.