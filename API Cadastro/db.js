import pkg from "pg";

const { Pool } = pkg;

async function connect() {

    if (global.connection) {
        return global.connection.connect();
    }

    const pool = new Pool({
        connectionString: process.env.DATABASE_URL
    });

    const client = await pool.connect();

    console.log("Criou o pool de conexao");

    const res = await client.query("select now()");
    console.log(res.rows[0]);

    client.release();

    global.connection = pool;

    return pool.connect();
}

export default connect; 