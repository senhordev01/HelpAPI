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

// ================= CRIPTO =================

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

    if (cpf.length !== 11 || /^(\d)\1+$/.test(cpf)){
       return false; 
    }

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


function normalizarCNPJ(cnpj) {
    return cnpj.replace(/\D/g, '');
}


function criptografarCNPJ(cnpj){
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algoritmo, chave, iv);

    let criptado = cipher.update(cnpj, 'utf8', 'hex');
    criptado += cipher.final('hex');

    return iv.toString('hex') + ':' + criptado;
}


function descriptografarCNPJ(cnpjCriptado) {
    const [ivHex, conteudo] = cnpjCriptado.split(':');

    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algoritmo, chave, iv);

    let descriptado = decipher.update(conteudo, 'hex', 'utf8');
    descriptado += decipher.final('utf8');

    return descriptado;
}


function hashCNPJ(cnpj) {
    return crypto.createHash('sha256').update(cnpj).digest('hex');
}

function mascararCNPJ(cnpj) {
    return cnpj.replace(
        /^(\d{2})\d{8}(\d{4})$/,
        '$1.********$2'
    );
}

function validarCNPJ(cnpj){
    cnpj = normalizarCNPJ(cnpj);
    if(cnpj.length !== 14 || /^(\d)\1+$/.test(cnpj)){
        return false;
    }

    let tamanho = 12;
    let numeros = cnpj.substring(0, tamanho);
    let digitos = cnpj.substring(tamanho);

    let soma = 0;
    let pos = tamanho - 7;

    // Primeiro dígito
    for (let i = tamanho; i >= 1; i--) {
        soma += Number(numeros[tamanho - i]) * pos--;

        if (pos < 2) {
            pos = 9;
        }
    }

    let resultado = soma % 11 < 2 ? 0 : 11 - (soma % 11);

    if (resultado !== Number(digitos[0])) {
        return false;
    }

    // Segundo dígito
    tamanho = 13;
    numeros = cnpj.substring(0, tamanho);

    soma = 0;
    pos = tamanho - 7;

    for (let i = tamanho; i >= 1; i--) {
        soma += Number(numeros[tamanho - i]) * pos--;

        if (pos < 2) {
            pos = 9;
        }
    }

    resultado = soma % 11 < 2 ? 0 : 11 - (soma % 11);

    return resultado === Number(digitos[1]);

}

// ================= TOKEN =================

function checar_token(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json("Token não enviado");
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(token, process.env.CHAVE_TOKEN);

        req.usuario = decoded;

        next();

    } catch (erro) {
        console.log(erro.message);
        return res.status(403).json("Token inválido");
    }
}
// ================= USUÁRIO =================

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
            msg: "Usuário cadastrado!",
            usuarioId: resultado.rows[0].usuarioid
        });

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

// ================= LOGIN =================

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

// ================= COMPARAÇÃO SEGURA =================

function verificarAcesso(req, id) {
    return Number(req.usuario.id) === Number(id);
}

// ================= ROTAS USUÁRIO =================

app.get("/usuarios/:id", checar_token, async (req, res) => {
    try {

        console.log("REQ.USUARIO:", req.usuario);
        console.log("PARAM ID:", req.params.id);

        const { id } = req.params;

        if (!verificarAcesso(req, id)) {
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
        const paramID = Number(req.params.id);
        const usuarioID = Number(req.usuario.id);

        console.log("JWT ID:", usuarioID);
        console.log("PARAM ID:", paramID);

        if (!usuarioID) {
            return res.status(403).json("Token inválido (sem ID)");
        }

        if (usuarioID !== paramID) {
            return res.status(403).json("Acesso negado");
        }

        const {nome, email} = req.body;
        const conexao = await db();

        const resultado = await conexao.query(
            `UPDATE Usuario SET nome=$1, email=$2 WHERE usuarioID=$3 RETURNING usuarioID`,
            [nome, email, paramID]

        );

        if (resultado.rowCount === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        res.status(200).json("Usuário Atualizado!");

    } catch (erro) {
        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

app.delete("/usuarios/:id", checar_token, async (req, res) => {
    try {
        const paramID = Number(req.params.id);
        const usuarioID = Number(req.usuario.id);

        console.log("JWT ID:", usuarioID);
        console.log("PARAM ID:", paramID);

        if (!usuarioID) {
            return res.status(403).json("Token inválido (sem ID)");
        }

        if (usuarioID !== paramID) {
            return res.status(403).json("Acesso negado");
        }

        const conexao = await db();

        const resultado = await conexao.query(
            "DELETE FROM Usuario WHERE usuarioID=$1 RETURNING usuarioID",
            [paramID]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json("Usuário não encontrado");
        }

        res.json("Usuário deletado");

    } catch (erro) {
        console.log("DELETE ERROR:", erro.message);
        res.status(500).json("Erro no servidor");
    }
});

// ================= ROTAS AUTONOMO =================
app.post("/tornar-autonomo", checar_token, async (req, res) => {
    try {
        let { profissao, cnpj } = req.body;

        if (!profissao || !cnpj) {
            return res.status(422).json("Campos obrigatórios estão faltando");
        }

        const usuarioID = Number(req.usuario?.id);

        if (!usuarioID) {
            return res.status(403).json("Token não contém ID válido");
        }

        cnpj = normalizarCNPJ(cnpj);

        if(!validarCNPJ(cnpj)){
            return res.status(422).json("CNPJ inválido");
        }

        const conexao = await db();

        const cnpjHash = hashCNPJ(cnpj);
        
        const usuarioExiste = await conexao.query(
            "SELECT 1 FROM Usuario WHERE usuarioID=$1",
            [usuarioID]
        );
        if (usuarioExiste.rows.length === 0) {
            return res.status(404).json("Usuário não existe");
        }


        const cnpjExiste = await conexao.query(
            "SELECT 1 FROM Autonomo WHERE cnpj_hash=$1",
            [cnpjHash]
        );

        if(cnpjExiste.rows.length > 0){
            return res.status(409).json("CNPJ já cadastrado!");
        }
        

        const existe = await conexao.query(
            "SELECT 1 FROM Autonomo WHERE usuarioID=$1",
            [usuarioID]
        );

        if (existe.rows.length > 0) {
            return res.status(409).json("Usuário já é autônomo");
        }

        const cnpjCriptado = criptografarCNPJ(cnpj);
    
        await conexao.query(
            `INSERT INTO Autonomo(usuarioID, profissao, cnpj, cnpj_hash)
             VALUES($1,$2,$3, $4)`,
            [usuarioID, profissao, cnpjCriptado, cnpjHash]
        );

        return res.status(201).json("Agora você é um autônomo!");

    } catch (erro) {
        console.log("Erro autonomo:", erro.message);
        return res.status(500).json("Erro no servidor");
    }
});

app.put("/autonomos/:id", checar_token, async (req, res) => {
    try {

        const autonomoID = Number(req.params.id);
        const usuarioID = Number(req.usuario.id);

        if (!usuarioID) {
            return res.status(403).json("Token inválido");
        }

        const { profissao } = req.body;

        if(!profissao){
            return res.status(422).json("Insira uma profissao");
        }

        const conexao = await db();

        // verifica se o autônomo pertence ao usuário
        const autonomo = await conexao.query(
            `SELECT 1 FROM Autonomo
             WHERE autonomoID=$1 AND usuarioID=$2`,

            [autonomoID, usuarioID]
        );

        if (autonomo.rows.length === 0) {
            return res.status(403).json("Acesso negado");
        }

        const resultado = await conexao.query(
            `UPDATE Autonomo
             SET profissao=$1
             WHERE autonomoID=$2
             RETURNING autonomoID`,

            [profissao, autonomoID]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json("Autônomo não encontrado");
        }

        res.status(200).json("Autônomo atualizado!");

    } catch (erro) {

        console.log(erro.message);

        res.status(500).json("Erro no servidor");
    }
});

app.delete("/autonomos/:id", checar_token, async (req, res) => {
    try {

        const autonomoID = Number(req.params.id);
        const usuarioID = Number(req.usuario.id);

        if (!usuarioID) {
            return res.status(403).json("Token inválido");
        }

        const conexao = await db();

        // verifica se o autônomo pertence ao usuário
        const autonomo = await conexao.query(
            `SELECT 1 FROM Autonomo
             WHERE autonomoID=$1 AND usuarioID=$2`,
            [autonomoID, usuarioID]
        );

        if (autonomo.rows.length === 0) {
            return res.status(403).json("Acesso negado");
        }

        const resultado = await conexao.query(
            `DELETE FROM Autonomo
             WHERE autonomoID=$1
             RETURNING autonomoID`,
            [autonomoID]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json("Autônomo não encontrado");
        }

        res.status(200).json("Autônomo deletado!");

    } catch (erro) {

        console.log(erro.message);

        res.status(500).json("Erro no servidor");
    }
});
// ================= Iniciar o Servidor =================

app.listen(porta, () => {
    console.log(`Servidor rodando na porta ${porta}`);
});