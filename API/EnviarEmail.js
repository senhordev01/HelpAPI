//npm init -y
//npm i nodemailer
//npm i dotenv

import 'dotenv/config';
import nodemailer from 'nodemailer';


const enviar = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_REMETENTE, //email do remetente
        pass: process.env.SENHA_REMETENTE, //senha da app do remetente
    }
});

enviar.sendMail({
    from: `Teste ${process.env.EMAIL_REMETENTE} `,//email do remetente
    to: '', //email do destinatario
    subject: 'Enviando com JavaScript',
    html: '<h1>Olá mundo!</h1>',
    text: 'Este email foi enviado usando Nodemailer com JavaScript'
})
.then(() => console.log('Email enviado com sucesso!'))
.catch((erro) => console.log('Erro ao enviar o email:', erro));