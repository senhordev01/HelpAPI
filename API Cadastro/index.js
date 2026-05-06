import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import db from './db.js';
import bcrypt, { genSalt } from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const app = express();
const porta = process.env.PORT;

app.use(express.json());
app.use(cors());

const algoritmo = 'aes-256-cbc';
const chave = Buffer.from(process.env.CHAVE_CRYPTO, 'hex');

function normalizarCPF(cpf) {
    return cpf.replace(/\D/g, '');
}

function criptografarCPF(cpf) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algoritmo, chave, iv);

    let criptado = cipher.update(cpf, 'utf8', 'hex');
    criptado += cipher.final('hex');

    return iv.toString('hex') + ':' + criptado;
}

function descriptografarCPF(cpfCriptado) {
    const [ivHex, conteudo] = cpfCriptado.split(':');

    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algoritmo, chave, iv);

    let descriptado = decipher.update(conteudo, 'hex', 'utf8');
    descriptado += decipher.final('utf8');

    return descriptado;
}

function hashCPF(cpf) {
    return crypto.createHash('sha256').update(cpf).digest('hex');
}

function mascararCPF(cpf) {
    return cpf.replace(/^(\d{3})\d{6}(\d{2})$/, '$1.***.***-$2');
}

function validarCPF(cpf) {
    cpf = normalizarCPF(cpf);

    if (cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) return false;

    let soma = 0;
    let resto;

    for (let i = 1; i <= 9; i++)
        soma += parseInt(cpf.substring(i - 1, i)) * (11 - i);

    resto = (soma * 10) % 11;
    if (resto >= 10) resto = 0;
    if (resto !== parseInt(cpf.substring(9, 10))) return false;

    soma = 0;
    for (let i = 1; i <= 10; i++)
        soma += parseInt(cpf.substring(i - 1, i)) * (12 - i);

    resto = (soma * 10) % 11;
    if (resto >= 10) resto = 0;

    return resto === parseInt(cpf.substring(10, 11));
}


function checar_token(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];

        if (!authHeader) {
            return res.status(401).json("Acesso negado");
        }

        const token = authHeader.split(' ')[1];

        if(!token){
            return res.status(401).json("token nao fornecido");
        }
        const chave_token = process.env.CHAVE_TOKEN;
        const decoded = jwt.verify(token, chave_token);
        req.usuario = decoded;
        next();

    } catch(erro) {
        console.log(erro.message);
        res.status(403).json("Token inválido");
    }
}

app.post("/usuarios", async (req, res) => {
    try {
        let { nome, cpf, dataNascimento, sexo, email, senha } = req.body;

        if (!nome || !cpf || !dataNascimento || !sexo || !email || !senha) {
            return res.status(422).json("Campos obrigatórios faltando");
        }

        cpf = normalizarCPF(cpf);

        if (!validarCPF(cpf)) {
            return res.status(422).json("CPF inválido!");
        }

        const conexao = await db();

        const emailExiste = await conexao.query(
            "SELECT 1 FROM Usuario WHERE email=$1",
            [email]
        );

        if (emailExiste.rows.length > 0) {
            return res.status(409).json("Email já cadastrado!");
        }

        const cpfHash = hashCPF(cpf);

        const cpfExiste = await conexao.query(
            "SELECT 1 FROM Usuario WHERE cpf_hash=$1",
            [cpfHash]
        );

        if (cpfExiste.rows.length > 0) {
            return res.status(409).json("CPF já cadastrado!");
        }

        const cpfCriptado = criptografarCPF(cpf);

        const salt = await genSalt(12);
        const senhaHash = await bcrypt.hash(senha, salt);

        const resultado = await conexao.query(
            `INSERT INTO Usuario(nome, cpf, cpf_hash, dataNascimento, sexo, email, senha)
             VALUES($1,$2,$3,$4,$5,$6,$7)
             RETURNING usuarioID`,
            [nome, cpfCriptado, cpfHash, dataNascimento, sexo, email, senhaHash]
        );

        res.status(201).json({
            Msg: "Usuário cadastrado!",
            usuarioId: resultado.rows[0].usuarioid
        });

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

app.get("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const { id } = req.params;

        if (req.usuario.id != id) {
            return res.status(403).json("Acesso negado");
        }

        const conexao = await db();

        const resultado = await conexao.query(
            "SELECT * FROM Usuario WHERE usuarioID=$1",
            [id]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        const usuario = resultado.rows[0];

        const cpfReal = descriptografarCPF(usuario.cpf);
        usuario.cpf = mascararCPF(cpfReal);

        delete usuario.senha;

        res.json(usuario);

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

app.put("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const { id } = req.params;
        let { nome, cpf, dataNascimento, sexo, email, senha } = req.body;

        if (req.usuario.id != id) {
            return res.status(403).json("Acesso negado");
        }

        const conexao = await db();

        const atual = await conexao.query(
            "SELECT * FROM Usuario WHERE usuarioID=$1",
            [id]
        );

        if (atual.rows.length === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        const user = atual.rows[0];

        // CPF
        let cpfCriptado = user.cpf;
        let cpfHash = user.cpf_hash;

        if (cpf) {
            cpf = normalizarCPF(cpf);

            if (!validarCPF(cpf)) {
                return res.status(422).json("CPF inválido!");
            }

            cpfCriptado = criptografarCPF(cpf);
            cpfHash = hashCPF(cpf);
        }

        // SENHA
        let senhaHash = user.senha;

        if (senha) {
            const salt = await genSalt(12);
            senhaHash = await bcrypt.hash(senha, salt);
        }

        await conexao.query(
            `UPDATE Usuario
             SET nome=$1, cpf=$2, cpf_hash=$3, dataNascimento=$4, sexo=$5, email=$6, senha=$7
             WHERE usuarioID=$8`,
            [
                nome || user.nome,
                cpfCriptado,
                cpfHash,
                dataNascimento || user.datanascimento,
                sexo || user.sexo,
                email || user.email,
                senhaHash,
                id
            ]
        );

        res.json("Usuário atualizado");

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

app.delete("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const { id } = req.params;

        if (req.usuario.id != id) {
            return res.status(403).json("Acesso negado");
        }

        const conexao = await db();

        await conexao.query(
            "DELETE FROM Usuario WHERE usuarioID=$1",
            [id]
        );

        res.json("Usuário deletado");

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, senha } = req.body;

        if (!email || !senha) {
            return res.status(422).json("Email e senha obrigatórios");
        }

        const conexao = await db();

        const resultado = await conexao.query(
            "SELECT * FROM Usuario WHERE email=$1",
            [email]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        const usuario = resultado.rows[0];

        const senhaValida = await bcrypt.compare(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json("Senha inválida");
        }

        const token = jwt.sign(
            { id: usuario.usuarioid, email: usuario.email },
            process.env.CHAVE_TOKEN,
            { expiresIn: "2h" }
        );

        res.json({
            mensagem: "Login realizado",
            token
        });

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

await db();

app.listen(porta, () => {
    console.log(`Servidor rodando na porta ${porta}`);
});