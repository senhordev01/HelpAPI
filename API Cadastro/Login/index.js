import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import db from './db.js';


const app = express();
const porta = process.env.PORT;

app.use(express.json());
app.use(cors());

// CRUD de dados dos usuarios cadastrados
app.post("/usuarios", async (req, res) => {
    try {

        const { nome, cpf, dataNascimento, sexo, email, senha  } = req.body;

        const conexao = await db();

        const sql = `
            INSERT INTO Usuario(nome, cpf, dataNascimento, sexo, email, senha)
            VALUES($1, $2, $3, $4, $5, $6)
        `;

        const usuarioExiste = await conexao.query(
            "SELECT * FROM Usuario WHERE email = $1",
            [email]
        );
        if(usuarioExiste.rows.length > 0){
            return res.status(409).json({Erro:"Usuario ja cadastrado!"});
        }

        await conexao.query(sql, [nome, cpf, dataNascimento, sexo, email, senha]);

        res.status(201).json("Usuario cadastrado!");

    } catch (erro) {

        console.log(erro.message);

        res.status(500).json("Erro no servidor");
    }
});
app.put("/usuarios/:id", async (req, res) => {

    try {

        const { id } = req.params;

        const { nome, cpf, dataNascimento, sexo, email, senha   } = req.body;

        const conexao = await db();

        await conexao.query(
            `
            UPDATE Usuario
            SET nome=$1, cpf=$2, dataNascimento=$3, sexo=$4, email=$5, senha=$5
            WHERE id = $6
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
            "DELETE FROM Usuario WHERE id = $1",
            [id]
        );

        res.status(200).json("Usuario deletado!");

    } catch (erro) {

        console.log(erro.message);

        res.status(500).json("Erro no servidor");
    }
});

//Parte de Login da API
app.post("/login", async(req, res)=>{
    try{

        const {email, senha} = req.body;
        const conexao = await db();

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

        //Realiza a verificaçao da senha
        if(usuario.senha != senha){
            return res.status(404).json({Erro: "Senha incorreta!"});
        }

        res.status(200).json({
            Mensagem: "Login realizado com sucesso!",
            id: usuario.usuarioid,
            nome: usuario.nome,
            senha: usuario.senha
        });
    }catch(erro){
        console.log(erro.message);
        res.status(500).json("Erro na conexao com o servidor");
    }
})
await db();


app.listen(porta, () => console.log(`Rodando na porta: ${porta}`));