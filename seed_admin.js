require("dotenv").config();
const bcrypt = require("bcrypt");
const pool = require("./db");

(async () => {
  try {
    const username = "caua.cezar";
    const email = "caua.cezar@cuidarconnect.com"; // pode ser seu email real
    const senha = "1234456"; // troque depois
    const nome = "Cauã Cezar";
    const perfil = "ADMIN";

    const hash = await bcrypt.hash(senha, 10);

    await pool.query(
      `
      INSERT INTO usuarios (nome, email, username, senha_hash, perfil, ativo)
      VALUES ($1,$2,$3,$4,$5,true)
      ON CONFLICT (username)
      DO UPDATE SET
        nome = EXCLUDED.nome,
        email = EXCLUDED.email,
        senha_hash = EXCLUDED.senha_hash,
        perfil = EXCLUDED.perfil,
        ativo = true,
        atualizado_em = NOW()
      `,
      [nome, email, username, hash, perfil]
    );

    console.log("✅ ADMIN pronto!");
    console.log("Login:", username, "ou", email);
    console.log("Senha:", senha);
  } catch (e) {
    console.error("❌ Erro seed:", e.message);
  } finally {
    await pool.end();
  }
})();
