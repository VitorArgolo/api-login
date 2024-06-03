const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const bodyParser = require('body-parser');
const authMiddleware = require('./authMiddleware');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'sua_chave_secreta_para_jwt';
const MONITORING_API_URL = 'https://api-monitoramento-1.onrender.com/logs';

app.use(cors()); // Middleware CORS global
app.use(bodyParser.json()); // Middleware body-parser para analisar JSON no corpo da requisição

// Conexão com o banco de dados SQLite
const db = new sqlite3.Database('./database.db', err => {
    if (err) {
        console.error(err.message);
        return;
    }
    // Cria a tabela de usuários 
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        phone TEXT
    )`, err => {
        if (err) {
            console.error(err.message);
            return;
        }
        console.log('Conectado ao banco de dados SQLite e tabela de usuários criada.');
    });
});

// Middleware para enviar logs para a API de monitoramento
app.use((req, res, next) => {
    const log = {
        timestamp: new Date(),
        method: req.method,
        path: req.path,
        body: req.body
    };

    axios.post(MONITORING_API_URL, log)
        .then(response => {
            console.log('Log enviado para API de monitoramento:', response.data);
        })
        .catch(error => {
            console.error('Erro ao enviar log para API de monitoramento:', error);
        });

    next();
});

// Rota para registro de usuário
app.post('/register', async (req, res) => {
    const { username, password, name, phone } = req.body;
    if (!username || !password || !name || !phone) {
        return res.status(400).json({ message: 'Por favor, forneça nome de usuário, senha, nome e telefone.' });
    }
    
    // Verificar se o email já está registrado no banco de dados
    const checkEmailQuery = `SELECT * FROM users WHERE username = ?`;
    db.get(checkEmailQuery, [username], async (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Erro ao verificar o email!' });
        }
        if (user) {
            return res.status(400).json({ message: 'Este email já está registrado!' });
        }
        
        // Se o email não estiver registrado, continue com o processo de registro
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = `INSERT INTO users (username, password, name, phone) VALUES (?, ?, ?, ?)`;

        db.run(sql, [username, hashedPassword, name, phone], err => {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ message: 'Erro ao registrar usuário!' });
            }
            res.json({ message: 'Usuário registrado com sucesso!' });
        });
    });
});

// Rota para login de usuário
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const sql = `SELECT * FROM users WHERE username = ?`;
    db.get(sql, [username], async (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Erro ao autenticar usuário!' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Credenciais inválidas!' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas!' });
        }
        const token = jwt.sign({ username }, SECRET_KEY);
        res.json({ token });
    });
});

// Nova rota para obter os detalhes do usuário logado
app.get('/me', authMiddleware, (req, res) => {
    const { username } = req.user;

    const sql = `SELECT username, name, phone FROM users WHERE username = ?`;
    db.get(sql, [username], (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Erro ao obter detalhes do usuário!' });
        }
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado!' });
        }
        res.json(user);
    });
});

// Rota para troca de senha
app.post('/change-password', authMiddleware, async (req, res) => {
    const { username } = req.user;
    const { oldPassword, newPassword } = req.body;

    // Busca o usuário no banco de dados
    const getUserQuery = `SELECT * FROM users WHERE username = ?`;
    db.get(getUserQuery, [username], async (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Erro ao buscar usuário!' });
        }

        // Verifica se a senha antiga corresponde à senha no banco de dados
        const passwordMatch = await bcrypt.compare(oldPassword, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Senha antiga incorreta!' });
        }

        // Gera o hash da nova senha
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Atualiza a senha no banco de dados
        const updatePasswordQuery = `UPDATE users SET password = ? WHERE username = ?`;
        db.run(updatePasswordQuery, [hashedNewPassword, username], err => {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ message: 'Erro ao atualizar senha!' });
            }
            res.json({ message: 'Senha atualizada com sucesso!' });
        });
    });
});

// Armazenar temporariamente os números de redefinição e os usuários associados
const passwordResetRequests = {};

// Configuração do serviço de e-mail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'emailatuomaticoenvio@gmail.com',
        pass: 'EmailAuto@tico123'
    }
});

// Função para enviar e-mail
const enviarEmail = async (destinatario, assunto, corpo) => {
    try {
        // Configurar informações do e-mail
        const mailOptions = {
            from
            : 'seu_email@example.com',
            to: destinatario,
            subject: assunto,
            text: corpo
        };

        // Enviar e-mail
        const info = await transporter.sendMail(mailOptions);
        console.log('E-mail enviado: ', info.messageId);
    } catch (error) {
        console.error('Erro ao enviar e-mail: ', error);
    }
};

// Rota para solicitar redefinição de senha
app.post('/forgot-password', async (req, res) => {
    const { username } = req.body;

    // Verificar se o usuário existe
    const sql = `SELECT * FROM users WHERE username = ?`;
    db.get(sql, [username], async (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Erro ao verificar usuário!' });
        }
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado!' });
        }

        // Gerar um token de redefinição de senha único
        const resetToken = uuidv4();

        // Armazenar o token de redefinição e o usuário associado temporariamente
        passwordResetRequests[resetToken] = username;

        // Enviar e-mail de redefinição de senha
        const destinatario = user.email; // Supondo que o e-mail do usuário esteja armazenado no campo 'email'
        const assunto = 'Redefinição de Senha';
        const corpo = `Olá ${user.username}, \n\nVocê solicitou a redefinição de senha. Use este token para redefinir sua senha: ${resetToken}. \n\nSe não foi você, ignore este e-mail.`;
        enviarEmail(destinatario, assunto, corpo);

        res.json({ message: 'E-mail de redefinição de senha enviado com sucesso!' });
    });
});

// Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
