import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import db from './db.js';
import bcrypt, { genSalt } from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
const porta = process.env.PORT;

app.use(express.json());
app.use(cors());

// CRUD de dados dos usuarios cadastrados
app.post("/usuarios", async (req, res) => {
    try {
        const { nome, cpf, dataNascimento, sexo, email, senha  } = req.body;
        if (!nome)return res.status(422).json("nome é obrigatório!");
        if (!cpf)return res.status(422).json("CPF é obrigatório!");
        if (!dataNascimento)return res.status(422).json("data de nascimento é obrigatória!");
        if (!sexo)return res.status(422).json("sexo da pessoa é obrigatório!");
        if (!email)return res.status(422).json("email é obrigatório!");
        if (!senha)return res.status(422).json("senha é obrigatória!");

        const conexao = await db();

        const usuarioExiste = await conexao.query(
            "SELECT * FROM Usuario WHERE email = $1",
            [email]
        );
        if(usuarioExiste.rows.length > 0){
            return res.status(409).json({Erro:"Usuario ja cadastrado!"});
        }

        const salt = await genSalt(12);
        const senhaHash = await bcrypt.hash(senha, salt);

        const sql = `
            INSERT INTO Usuario(nome, cpf, dataNascimento, sexo, email, senha)
            VALUES($1, $2, $3, $4, $5, $6)
            RETURNING usuarioID
        `;

        const resultado = await conexao.query(sql, [nome, cpf, dataNascimento, sexo, email, senhaHash]);
        const usuarioId = resultado.rows[0].usuarioid;

        res.status(201).json({Msg:"Usuario cadastrado com sucesso!", usuarioId} );

    } catch (erro) {

        console.log(erro.message);

        res.status(500).json("Erro no servidor");
    }
});
app.put("/usuarios/:id", async (req, res) => {

    try {

        const { id } = req.params;

        const { nome, cpf, dataNascimento, sexo, email, senha} = req.body;

        const conexao = await db();

        await conexao.query(
            `
            UPDATE Usuario
            SET nome=$1, cpf=$2, dataNascimento=$3, sexo=$4, email=$5, senha=$6
            WHERE usuarioID= $7
            `,
            [nome, cpf, dataNascimento, sexo, email, senha, id]
        );

        res.status(200).json("Usuario atualizado!");

    } catch (erro) {

        console.log(erro.message);

        res.status(500).json("Erro no servidor");
    }
});

app.delete("/usuarios/:id", async (req, res) => {

    try {

        const { id } = req.params;
        const conexao = await db();
        await conexao.query(
            "DELETE FROM Usuario WHERE usuarioID = $1",
            [id]
        );
        res.status(200).json("Usuario deletado!");

    } catch (erro) {

        console.log(erro.message);
        res.status(500).json("Erro no servidor");
    }
});

function checar_token(req, res, next){
    try{
        const authHeader = req.headers['authorization'];
        if(!authHeader){
            return res.status(401).json("Acesso negado")
        }
        const token = authHeader.split(' ')[1];
        if(!token){
            return res.status(401).json("token nao fornecido");
        }
        const chave_token = process.env.CHAVE_TOKEN;
        const decoded = jwt.verify(token, chave_token);
        req.usuario = decoded;
        next();

    }catch(erro){
        console.log(erro.message);
        res.status(403).json("token invalido");
    }
}

app.get('/usuarios/:id', checar_token, async(req,res)=>{
    try{
        const id = req.params.id;
        const conexao = await db();
        const usuario = await conexao.query(
            "SELECT usuarioID, nome, cpf, dataNascimento, sexo, email, senha FROM Usuario WHERE usuarioID=$1",
            [id]
        );
        if(!usuario){
            return res.status(404).json("Usuario nao encontrado!");
        }
        res.json(usuario.rows[0]);
    }catch(erro){
        console.log(erro.message)
        res.status(500).json("Erro no servidor")
    }
});

//Parte de Login da API
app.post("/login", async(req, res)=>{
    try{
        const {email, senha} = req.body;
        const conexao = await db();
        if(!email || !senha){
            return res.status(422).json("email e senha sao obrigatórios!");
        }
        const resultado = await conexao.query(
            `
            SELECT * FROM Usuario
            WHERE email = $1
            `,
            [email]
        );

        //Realiza a verificaçao da existencia de usuarios cadastrados
        if(resultado.rows.length === 0){
            return res.status(404).json({Erro: "Usuario nao encontrado!"});
        }

        const usuario = resultado.rows[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha)
        //Realiza a verificaçao da senha
        if(!senhaValida){
            return res.status(401).json("Senha inválida!");
        }

        const chave_token = process.env.CHAVE_TOKEN;

        const token = jwt.sign(
            {id: usuario.usuarioid, email: usuario.email},
            chave_token,
            {expiresIn:"1h"}
        )

        res.status(200).json({
            Mensagem: "Login realizado com sucesso!",
            token
        });

    }catch(erro){
        console.log(erro.message);
        res.status(500).json("Erro na conexao com o servidor");
    }
});

await db();

app.listen(porta, () => console.log(`Rodando na porta: ${porta}`));