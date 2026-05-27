import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';

const app = express();
const porta = 3000;

app.use(cors());
app.use(express.json());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_REMETENTE, //email do remetente
    pass: process.env.SENHA_REMETENTE //senha do remetente
  }
});

app.get('/enviar', async (req, res) => {
  const codigo = Math.floor(Math.random() * 90000) + 10000;

  const html = `
  <!DOCTYPE html>
  <html lang="pt-br">
  <body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;">

    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td
          align="center"
          bgcolor="rgb(15, 88, 0)"
          style="padding:24px;"
        >
          <h1 style="margin:0;color:white;">
            Seja Bem-Vindo(a) ao Help
          </h1>
        </td>
      </tr>

      <tr>
        <td
          align="center"
          style="padding:80px 20px;"
        >

          <p style="font-size:18px;margin-bottom:20px;">
            Aqui está seu código de verificação para confirmar seu e-mail
          </p>

          <p
            style="
              font-size:50px;
              font-weight:bold;
              letter-spacing:5px;
              margin:0;
            "
          >
            ${codigo}
          </p>

        </td>
      </tr>
    </table>

  </body>
  </html>
  `;

  try {
    await transporter.sendMail({
      from: `Help <${process.env.EMAIL_REMETENTE}>`,
      to: '',//email do destinatario
      subject: 'Código de verificação',
      html
    });

    res.status(200).json({ codigo });

  } catch (erro) {
    console.error(erro);

    res.status(500).json({
      erro: erro.message
    });
  }
});

app.listen(porta, () => {
  console.log(`Servidor rodando na porta ${porta}`);
});