const jwt = require('jsonwebtoken');
const SECRET_KEY = 'sua_chave_secreta_para_jwt';

function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.sendStatus(401); // Não autorizado se o token não estiver presente
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Proibido se o token não for válido
        }
        req.user = user; // Adiciona o usuário ao objeto de requisição
        next();
    });
}

module.exports = authMiddleware;
