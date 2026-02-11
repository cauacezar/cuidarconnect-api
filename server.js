require("dotenv").config();
const express = require("express");
const pool = require("./db");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;

const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const JWT_SECRET = process.env.JWT_SECRET || "troque-essa-chave";


function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: "Sem token." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, nome, email, perfil }
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "Token inválido." });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const perfil = req.user?.perfil;
    if (!perfil) return res.status(401).json({ ok:false, error:"Sem usuário." });

    if (perfil === "ADMIN") return next();
    if (roles.includes(perfil)) return next();

    return res.status(403).json({ ok:false, error:"Acesso negado." });
  };
}


app.post("/auth/login", async (req, res) => {
  try {
    const login = String(req.body.email || "").trim().toLowerCase();
    const senha = String(req.body.senha || "");

    if (!login || !senha) return res.status(400).json({ ok:false, error:"Email e senha são obrigatórios." });

    const r = await pool.query(
      `SELECT id, nome, email, username, senha_hash, perfil, ativo FROM usuarios  WHERE lower(email) = $1 OR lower(username) = $1 LIMIT 1`,
      [login]
    );
    if (!r.rows.length) return res.status(400).json({ ok:false, error:"Usuário ou senha inválidos." });

    const u = r.rows[0];
    if (!u.ativo) return res.status(403).json({ ok:false, error:"Usuário inativo." });

    const ok = await bcrypt.compare(senha, u.senha_hash);
    if (!ok) return res.status(400).json({ ok:false, error:"Usuário ou senha inválidos." });

    const token = jwt.sign(
      { id: u.id, nome: u.nome, email: u.email, username: u.username, perfil: u.perfil },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      ok: true,
      token,
      user: { id: u.id, nome: u.nome, email: u.email, username: u.username, perfil: u.perfil }
    });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});

// LISTAR
app.get("/usuarios", authMiddleware, requireRole("ADMIN"), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, nome, email, perfil, ativo, criado_em
       FROM usuarios
       ORDER BY id DESC`
    );
    res.json({ ok:true, data:r.rows });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});

// CRIAR
app.post("/usuarios", authMiddleware, requireRole("ADMIN"), async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const nome = String(req.body.nome || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const senha = String(req.body.senha || "");
    const perfil = String(req.body.perfil || "CADASTROS").trim().toUpperCase();
    const ativo = req.body.ativo === false ? false : true;

    if (!username) return res.status(400).json({ ok:false, error:"Usuário é obrigatório." });
    if (!/^[a-z0-9._-]{3,60}$/.test(username))
    return res.status(400).json({ ok:false, error:"Usuário inválido. Use letras/números e . _ - (3 a 60)." });

    if (!nome) return res.status(400).json({ ok:false, error:"Nome é obrigatório." });
    if (!email) return res.status(400).json({ ok:false, error:"Email é obrigatório." });
    if (senha.length < 6) return res.status(400).json({ ok:false, error:"Senha deve ter no mínimo 6 caracteres." });

    if (!["ADMIN","FINANCEIRO","CADASTROS"].includes(perfil))
      return res.status(400).json({ ok:false, error:"Perfil inválido." });

    const hash = await bcrypt.hash(senha, 10);

    const r = await pool.query(
      `INSERT INTO usuarios (nome, email, username, senha_hash, perfil, ativo)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id`,
      [nome, email, username, hash, perfil, ativo]
    );

    res.json({ ok:true, id:r.rows[0].id });
  } catch (e) {
    // email duplicado
    if (String(e.message || "").includes("duplicate key")) {
      return res.status(400).json({ ok:false, error:"Já existe um usuário com esse email." });
    }
    res.status(500).json({ ok:false, error:e.message });
  }
});

// ATUALIZAR (nome/perfil/ativo)
app.put("/usuarios/:id", authMiddleware, requireRole("ADMIN"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok:false, error:"ID inválido." });

    const nome = String(req.body.nome || "").trim();
    const perfil = String(req.body.perfil || "").trim().toUpperCase();
    const ativo = req.body.ativo === false ? false : true;

    if (!nome) return res.status(400).json({ ok:false, error:"Nome é obrigatório." });
    if (!["ADMIN","FINANCEIRO","CADASTROS"].includes(perfil))
      return res.status(400).json({ ok:false, error:"Perfil inválido." });

    const r = await pool.query(
      `UPDATE usuarios
       SET nome=$1, perfil=$2, ativo=$3, atualizado_em=NOW()
       WHERE id=$4
       RETURNING id, nome, email, perfil, ativo`,
      [nome, perfil, ativo, id]
    );

    if (!r.rows.length) return res.status(404).json({ ok:false, error:"Usuário não encontrado." });
    res.json({ ok:true, user:r.rows[0] });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});

// RESET SENHA
app.put("/usuarios/:id/reset-senha", authMiddleware, requireRole("ADMIN"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const senha = String(req.body.senha || "");
    if (!id) return res.status(400).json({ ok:false, error:"ID inválido." });
    if (senha.length < 6) return res.status(400).json({ ok:false, error:"Senha deve ter no mínimo 6 caracteres." });

    const hash = await bcrypt.hash(senha, 10);

    const r = await pool.query(
      `UPDATE usuarios SET senha_hash=$1, atualizado_em=NOW() WHERE id=$2 RETURNING id`,
      [hash, id]
    );
    if (!r.rows.length) return res.status(404).json({ ok:false, error:"Usuário não encontrado." });

    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});



app.get("/inadimplencia/lista", authMiddleware, requireRole("ADMIN","FINANCEIRO"), async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const motivo = String(req.query.motivo || "").trim().toUpperCase(); // BOLETO_PENDENTE / PIX_PENDENTE / ATRASO_60D
    const fp = String(req.query.fp || "").trim().toUpperCase();         // forma_pagamento do titular

    const where = [];
    const params = [];

    if (q) {
      params.push(`%${q}%`);
      where.push(`(nome ILIKE $${params.length} OR cpf ILIKE $${params.length} OR telefone ILIKE $${params.length})`);
    }

    if (fp) {
      params.push(fp);
      where.push(`forma_pagamento = $${params.length}`);
    }

    if (motivo) {
      params.push(motivo);
      where.push(`motivo = $${params.length}`);
    }

    const sql = `
      WITH pend AS (
        SELECT
          p.titular_id,
          MIN(p.data_referencia) AS menor_ref,
          COUNT(*) FILTER (WHERE upper(p.status::text)='PENDENTE')::int AS pend_qtd,
          COUNT(*) FILTER (WHERE upper(p.status::text)='PENDENTE' AND upper(p.tipo::text)='BOLETO')::int AS bol_qtd,
          COUNT(*) FILTER (WHERE upper(p.status::text)='PENDENTE' AND upper(p.tipo::text)='PIX')::int AS pix_qtd
        FROM pagamentos p
        WHERE upper(p.status::text)='PENDENTE'
        GROUP BY p.titular_id
      ),
      base AS (
        SELECT
          t.id,
          t.nome,
          t.cpf,
          t.telefone,
          upper(t.forma_pagamento::text) AS forma_pagamento,
          upper(t.status::text) AS status_titular,
          pnd.pend_qtd,
          pnd.bol_qtd,
          pnd.pix_qtd,
          pnd.menor_ref,
          pl.titulo AS plano_titulo,
          (SELECT COUNT(*)::int FROM dependentes d WHERE d.titular_id = t.id) AS dependentes,
          0::int AS alertas_pendentes,
          CASE
            WHEN COALESCE(pnd.bol_qtd,0) > 0 THEN 'BOLETO_PENDENTE'
            WHEN COALESCE(pnd.pix_qtd,0) > 0 THEN 'PIX_PENDENTE'
            WHEN pnd.menor_ref IS NOT NULL AND pnd.menor_ref <= (CURRENT_DATE - INTERVAL '60 days') THEN 'ATRASO_60D'
            ELSE 'BOLETO_PENDENTE'
          END AS motivo
        FROM titulares t
        JOIN planos pl ON pl.id = t.plano_id
        LEFT JOIN pend pnd ON pnd.titular_id = t.id
        WHERE
          upper(t.status::text)='INADIMPLENTE'
          OR (pnd.pend_qtd IS NOT NULL AND pnd.pend_qtd > 0 AND (pnd.menor_ref IS NULL OR pnd.menor_ref < CURRENT_DATE))
      )
      SELECT *
      FROM base
      WHERE 1=1
      ${where.length ? " AND " + where.join(" AND ") : ""}
      ORDER BY (status_titular='INADIMPLENTE') DESC, pend_qtd DESC, id DESC
    `;

    const r = await pool.query(sql, params);
    res.json({ ok:true, data: r.rows });
  } catch (e) {
    console.error("ERRO /inadimplencia/lista:", e);
    res.status(500).json({ ok:false, error:e.message });
  }
});






/* ===========================
   Utils
   =========================== */
function onlyDigits(s) {
  return (s || "").toString().replace(/\D/g, "");
}

function asDateOnlyISO(d) {
  // d pode ser "YYYY-MM-DD" ou null
  if (!d) return null;
  return String(d).slice(0, 10);
}

// ✅ Regra automática: se vigência acabou e está ATIVO -> INADIMPLENTE
async function aplicarRegraVigenciaExpirada() {
  try {
    await pool.query(`
      UPDATE titulares
      SET status = 'INADIMPLENTE',
          atualizado_em = NOW()
      WHERE status = 'ATIVO'
        AND vigencia_fim IS NOT NULL
        AND vigencia_fim < CURRENT_DATE;
    `);

    await pool.query(`
      UPDATE dependentes d
      SET status = 'INADIMPLENTE'
      FROM titulares t
      WHERE d.titular_id = t.id
        AND t.status = 'INADIMPLENTE'
        AND t.vigencia_fim IS NOT NULL
        AND t.vigencia_fim < CURRENT_DATE;
    `);
  } catch (e) {
    console.warn("Aviso: falha ao aplicar regra de vigência:", e.message);
  }
}

/* ===========================
   Rotas básicas
   =========================== */
app.get("/", (req, res) => res.send("API Cuidar Connect está rodando"));

app.get("/db-check", async (req, res) => {
  try {
    const now = await pool.query("SELECT NOW() as now");
    const db = await pool.query("SELECT current_database() as db");
    const tables = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
      ORDER BY table_name;
    `);

    res.json({
      ok: true,
      database: db.rows[0].db,
      now: now.rows[0].now,
      tables: tables.rows.map(t => t.table_name),
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* ===========================
   PLANOS
   =========================== */
app.get("/planos", async (req, res) => {
  try {
    const q = (req.query.q || "").trim();
    const status = (req.query.status || "").trim().toUpperCase();

    const where = [];
    const params = [];

    if (q) {
      params.push(`%${q}%`);
      where.push(`titulo ILIKE $${params.length}`);
    }
    if (status === "ATIVO" || status === "INATIVO") {
      params.push(status);
      where.push(`status = $${params.length}`);
    }

    const sql = `
      SELECT id, titulo, descricao, valor, tempo_contrato_meses, status, criado_em, atualizado_em
      FROM planos
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY id DESC
    `;

    const r = await pool.query(sql, params);
    res.json({ ok: true, data: r.rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/planos/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(
      `SELECT id, titulo, descricao, valor, tempo_contrato_meses, status
       FROM planos WHERE id=$1`,
      [id]
    );
    if (!r.rows.length) return res.status(404).json({ ok: false, error: "Plano não encontrado." });
    res.json({ ok: true, data: r.rows[0] });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/planos", async (req, res) => {
  try {
    const { titulo, descricao, valor, tempo_contrato_meses, status } = req.body;

    if (!titulo || !String(titulo).trim()) {
      return res.status(400).json({ ok: false, error: "Título é obrigatório." });
    }

    const v = Number(valor);
    const meses = Number(tempo_contrato_meses);
    if (!(v > 0)) return res.status(400).json({ ok: false, error: "Valor inválido." });
    if (!(meses > 0)) return res.status(400).json({ ok: false, error: "Tempo de contrato inválido." });

    const st = (status || "ATIVO").toUpperCase();
    if (!["ATIVO", "INATIVO"].includes(st)) {
      return res.status(400).json({ ok: false, error: "Status inválido." });
    }

    const r = await pool.query(
      `INSERT INTO planos (titulo, descricao, valor, tempo_contrato_meses, status)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id`,
      [String(titulo).trim(), descricao ? String(descricao).trim() : null, v, meses, st]
    );

    res.json({ ok: true, id: r.rows[0].id });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.put("/planos/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { titulo, descricao, valor, tempo_contrato_meses, status } = req.body;

    if (!titulo || !String(titulo).trim()) {
      return res.status(400).json({ ok: false, error: "Título é obrigatório." });
    }

    const v = Number(valor);
    const meses = Number(tempo_contrato_meses);
    if (!(v > 0)) return res.status(400).json({ ok: false, error: "Valor inválido." });
    if (!(meses > 0)) return res.status(400).json({ ok: false, error: "Tempo de contrato inválido." });

    const st = (status || "ATIVO").toUpperCase();
    if (!["ATIVO", "INATIVO"].includes(st)) {
      return res.status(400).json({ ok: false, error: "Status inválido." });
    }

    const r = await pool.query(
      `UPDATE planos
       SET titulo=$1, descricao=$2, valor=$3, tempo_contrato_meses=$4, status=$5
       WHERE id=$6
       RETURNING id`,
      [String(titulo).trim(), descricao ? String(descricao).trim() : null, v, meses, st, id]
    );

    if (!r.rows.length) return res.status(404).json({ ok: false, error: "Plano não encontrado." });
    res.json({ ok: true, id: r.rows[0].id });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* ===========================
   TITULARES - CRIAR (com vigência + endereço separado)
   =========================== */
app.post("/titulares", async (req, res) => {
  const { titular, dependentes = [] } = req.body || {};
  const client = await pool.connect();

  try {
    if (!titular) return res.status(400).json({ ok: false, error: "Payload inválido." });

    const plano_id = Number(titular.plano_id);
    if (!plano_id) return res.status(400).json({ ok: false, error: "plano_id é obrigatório." });

    const nome = String(titular.nome || "").trim();
    if (!nome) return res.status(400).json({ ok: false, error: "Nome do titular é obrigatório." });

    const cpf = onlyDigits(titular.cpf);
    if (cpf.length !== 11) return res.status(400).json({ ok: false, error: "CPF do titular inválido." });

    const tel = onlyDigits(titular.telefone);
    if (tel.length < 10) return res.status(400).json({ ok: false, error: "Telefone do titular inválido." });

    const forma = String(titular.forma_pagamento || "").toUpperCase();
    if (!["PIX", "CARTAO_AVISTA", "CARTAO_12X", "BOLETO"].includes(forma))
      return res.status(400).json({ ok: false, error: "Forma de pagamento inválida." });

    const statusInicial = String(titular.status_inicial || "INADIMPLENTE").toUpperCase();
    if (!["ATIVO", "INADIMPLENTE", "CANCELADO"].includes(statusInicial))
      return res.status(400).json({ ok: false, error: "Status inicial inválido." });

    const dia_venc = titular.dia_vencimento ? Number(titular.dia_vencimento) : null;
    if (dia_venc !== null && (dia_venc < 1 || dia_venc > 28))
      return res.status(400).json({ ok: false, error: "Dia de vencimento deve ser 1 a 28." });

    // ✅ Vigência: início vem do front (opcional), se não vier -> hoje
    const vigencia_inicio = asDateOnlyISO(titular.vigencia_inicio) || new Date().toISOString().slice(0, 10);

    await client.query("BEGIN");

    // Pega meses do plano
    const p = await client.query(
      `SELECT tempo_contrato_meses, status FROM planos WHERE id=$1 LIMIT 1`,
      [plano_id]
    );
    if (!p.rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "Plano não encontrado." });
    }
    if (String(p.rows[0].status || "").toUpperCase() !== "ATIVO") {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "Plano está INATIVO." });
    }

    const meses = Number(p.rows[0].tempo_contrato_meses || 0);
    if (!(meses > 0)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "Plano com tempo_contrato_meses inválido." });
    }

    // ✅ vigencia_fim = vigencia_inicio + meses (date)
    const vigencia_fim_res = await client.query(
      `SELECT ($1::date + ($2 || ' months')::interval)::date AS fim`,
      [vigencia_inicio, meses]
    );
    const vigencia_fim = vigencia_fim_res.rows[0].fim;

    const rTitular = await client.query(
      `INSERT INTO titulares
       (plano_id, nome, cpf, data_nascimento, telefone, email,
        forma_pagamento, dia_vencimento, status,
        vigencia_inicio, vigencia_fim,
        cep, logradouro, numero, complemento, bairro, cidade, uf)
       VALUES
       ($1,$2,$3,$4,$5,$6,
        $7,$8,$9,
        $10,$11,
        $12,$13,$14,$15,$16,$17,$18)
       RETURNING id`,
      [
        plano_id,
        nome,
        cpf,
        titular.data_nascimento || null,
        tel,
        titular.email ? String(titular.email).trim() : null,

        forma,
        dia_venc,
        statusInicial,

        vigencia_inicio,
        vigencia_fim,

        onlyDigits(titular.cep).slice(0, 8) || null,
        titular.logradouro ? String(titular.logradouro).trim() : null,
        titular.numero ? String(titular.numero).trim() : null,
        titular.complemento ? String(titular.complemento).trim() : null,
        titular.bairro ? String(titular.bairro).trim() : null,
        titular.cidade ? String(titular.cidade).trim() : null,
        titular.uf ? String(titular.uf).trim().toUpperCase().slice(0, 2) : null,
      ]
    );

    const titular_id = rTitular.rows[0].id;

    for (const d of dependentes) {
      const dNome = String(d.nome || "").trim();
      if (!dNome) continue;

      const dCpf = d.cpf ? onlyDigits(d.cpf) : null;
      if (dCpf && dCpf.length !== 11)
        return res.status(400).json({ ok: false, error: "CPF de dependente inválido: " + dNome });

      const dTel = d.telefone ? onlyDigits(d.telefone) : null;

      await client.query(
        `INSERT INTO dependentes
         (titular_id, nome, cpf, data_nascimento, parentesco, telefone, status)
         VALUES
         ($1,$2,$3,$4,$5,$6,$7)`,
        [
          titular_id,
          dNome,
          dCpf,
          d.data_nascimento || null,
          d.parentesco ? String(d.parentesco).trim() : null,
          dTel,
          statusInicial,
        ]
      );
    }

    await client.query("COMMIT");
    res.json({ ok: true, id: titular_id });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ ok: false, error: e.message });
  } finally {
    client.release();
  }
});

/* ===========================
   LISTAR TITULARES (com vigência)
   =========================== */
app.get("/titulares", async (req, res) => {
  try {
    await aplicarRegraVigenciaExpirada();

    const q = (req.query.q || "").trim();
    const params = [];
    let where = "";

    if (q) {
      params.push(`%${q}%`);
      where = `WHERE t.nome ILIKE $1 OR t.cpf ILIKE $1 OR t.telefone ILIKE $1`;
    }

    const r = await pool.query(
      `
      SELECT
        t.id,
        t.nome,
        t.cpf,
        t.telefone,
        t.email,
        t.status,
        t.forma_pagamento,
        t.dia_vencimento,
        t.vigencia_inicio,
        t.vigencia_fim,
        t.criado_em,
        p.titulo AS plano_titulo,
        p.valor AS plano_valor
      FROM titulares t
      INNER JOIN planos p ON p.id = t.plano_id
      ${where}
      ORDER BY t.id DESC
      `,
      params
    );

    res.json({ ok: true, data: r.rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* ===========================
   DETALHE DO TITULAR
   =========================== */
app.get("/titulares/:id", async (req, res) => {
  try {
    await aplicarRegraVigenciaExpirada();

    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok: false, error: "ID inválido" });

    const titularRes = await pool.query(
      `
      SELECT
        t.id,
        t.nome,
        t.cpf,
        t.data_nascimento,
        t.telefone,
        t.email,
        t.forma_pagamento,
        t.dia_vencimento,
        t.status,

        t.vigencia_inicio,
        t.vigencia_fim,

        t.cep,
        t.logradouro,
        t.numero,
        t.complemento,
        t.bairro,
        t.cidade,
        t.uf,

        p.titulo AS plano_titulo,
        p.valor AS plano_valor,
        p.tempo_contrato_meses
      FROM titulares t
      INNER JOIN planos p ON p.id = t.plano_id
      WHERE t.id = $1
      LIMIT 1
      `,
      [id]
    );

    if (!titularRes.rows.length) {
      return res.status(404).json({ ok: false, error: "Titular não encontrado" });
    }

    const depsRes = await pool.query(
      `
      SELECT id, nome, cpf, telefone, parentesco, status
      FROM dependentes
      WHERE titular_id = $1
      ORDER BY id ASC
      `,
      [id]
    );

    res.json({ ok: true, titular: titularRes.rows[0], dependentes: depsRes.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ===========================
   ATUALIZAR TITULAR (dados + endereço separado)
   =========================== */
app.put("/titulares/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok: false, error: "ID inválido." });

    const {
      nome,
      data_nascimento,
      telefone,
      email,

      cep,
      logradouro,
      numero,
      complemento,
      bairro,
      cidade,
      uf
    } = req.body || {};

    if (!nome || !String(nome).trim()) {
      return res.status(400).json({ ok: false, error: "Nome é obrigatório." });
    }

    const tel = onlyDigits(telefone);
    if (tel.length < 10) return res.status(400).json({ ok: false, error: "Telefone inválido." });

    const r = await pool.query(
      `
      UPDATE titulares
      SET
        nome = $1,
        data_nascimento = $2,
        telefone = $3,
        email = $4,

        cep = $5,
        logradouro = $6,
        numero = $7,
        complemento = $8,
        bairro = $9,
        cidade = $10,
        uf = $11
      WHERE id = $12
      RETURNING id, nome, cpf, telefone, email, status, forma_pagamento,
                cep, logradouro, numero, complemento, bairro, cidade, uf,
                vigencia_inicio, vigencia_fim;
      `,
      [
        String(nome).trim(),
        data_nascimento || null,
        tel,
        email ? String(email).trim() : null,

        onlyDigits(cep).slice(0, 8) || null,
        logradouro ? String(logradouro).trim() : null,
        numero ? String(numero).trim() : null,
        complemento ? String(complemento).trim() : null,
        bairro ? String(bairro).trim() : null,
        cidade ? String(cidade).trim() : null,
        uf ? String(uf).trim().toUpperCase().slice(0, 2) : null,

        id
      ]
    );

    if (!r.rows.length) return res.status(404).json({ ok: false, error: "Titular não encontrado." });

    res.json({ ok: true, titular: r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* ===========================
   CANCELAR PLANO DO TITULAR
   =========================== */
app.put("/titulares/:id/cancelar", async (req, res) => {
  const client = await pool.connect();
  try {
    const titular_id = Number(req.params.id);
    if (!titular_id) return res.status(400).json({ ok:false, error:"ID inválido." });

    const motivo = req.body.motivo ? String(req.body.motivo).trim() : null;

    await client.query("BEGIN");

    const r = await client.query(
      `UPDATE titulares
       SET status='CANCELADO',
           cancelado_em=NOW(),
           cancel_motivo=$2
       WHERE id=$1
       RETURNING id, status, cancelado_em`,
      [titular_id, motivo]
    );

    if (!r.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ ok:false, error:"Titular não encontrado." });
    }

    await client.query(`UPDATE dependentes SET status='CANCELADO' WHERE titular_id=$1`, [titular_id]);

    await client.query("COMMIT");
    return res.json({ ok:true, titular: r.rows[0] });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    return res.status(500).json({ ok:false, error:e.message });
  } finally {
    client.release();
  }
});

/* ===========================
   TROCAR PLANO DO TITULAR (reinicia vigência)
   =========================== */
app.put("/titulares/:id/trocar-plano", async (req, res) => {
  const client = await pool.connect();
  try {
    const titular_id = Number(req.params.id);
    if (!titular_id) return res.status(400).json({ ok: false, error: "ID inválido." });

    const novo_plano_id = Number(req.body.novo_plano_id || 0);
    const motivo = req.body.motivo ? String(req.body.motivo).trim() : null;
    const vigencia_inicio = asDateOnlyISO(req.body.vigencia_inicio) || new Date().toISOString().slice(0,10);

    if (!novo_plano_id) {
      return res.status(400).json({ ok: false, error: "novo_plano_id é obrigatório." });
    }

    await client.query("BEGIN");

    const t = await client.query(`SELECT id, plano_id FROM titulares WHERE id=$1 LIMIT 1`, [titular_id]);
    if (!t.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ ok: false, error: "Titular não encontrado." });
    }

    const plano_atual_id = Number(t.rows[0].plano_id || 0);
    if (plano_atual_id === novo_plano_id) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "O titular já está neste plano." });
    }

    const p = await client.query(
      `SELECT id, status, tempo_contrato_meses FROM planos WHERE id=$1 LIMIT 1`,
      [novo_plano_id]
    );
    if (!p.rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "Plano não encontrado." });
    }
    if (String(p.rows[0].status).toUpperCase() !== "ATIVO") {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "Plano selecionado não está ATIVO." });
    }

    const meses = Number(p.rows[0].tempo_contrato_meses || 0);
    if (!(meses > 0)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "Plano com tempo_contrato_meses inválido." });
    }

    const fimRes = await client.query(
      `SELECT ($1::date + ($2 || ' months')::interval)::date AS fim`,
      [vigencia_inicio, meses]
    );
    const vigencia_fim = fimRes.rows[0].fim;

    await client.query(
      `UPDATE titulares
       SET plano_id=$1,
           status='INADIMPLENTE',
           vigencia_inicio=$2,
           vigencia_fim=$3,
           atualizado_em=NOW()
       WHERE id=$4`,
      [novo_plano_id, vigencia_inicio, vigencia_fim, titular_id]
    );

    await client.query(
      `UPDATE dependentes
       SET status='INADIMPLENTE'
       WHERE titular_id=$1`,
      [titular_id]
    );

    // histórico (se existir)
    try {
      await client.query(
        `INSERT INTO titular_historico_planos (titular_id, plano_anterior_id, plano_novo_id, motivo)
         VALUES ($1,$2,$3,$4)`,
        [titular_id, plano_atual_id || null, novo_plano_id, motivo]
      );
    } catch (_) {}

    await client.query("COMMIT");
    return res.json({ ok: true, plano_anterior_id: plano_atual_id, plano_novo_id: novo_plano_id });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    return res.status(500).json({ ok: false, error: e.message });
  } finally {
    client.release();
  }
});

/* ===========================
   DEPENDENTES (mantidos)
   =========================== */
app.post("/titulares/:id/dependentes", async (req, res) => {
  try {
    const titular_id = Number(req.params.id);
    if (!titular_id) return res.status(400).json({ ok: false, error: "ID do titular inválido." });

    const nome = String(req.body.nome || "").trim();
    const cpf = req.body.cpf ? onlyDigits(req.body.cpf) : null;
    const telefone = req.body.telefone ? onlyDigits(req.body.telefone) : null;
    const parentesco = req.body.parentesco ? String(req.body.parentesco).trim() : null;
    const data_nascimento = req.body.data_nascimento || null;

    if (!nome) return res.status(400).json({ ok: false, error: "Nome do dependente é obrigatório." });
    if (cpf && cpf.length !== 11) return res.status(400).json({ ok: false, error: "CPF do dependente inválido (11 dígitos)." });

    const t = await pool.query(`SELECT status, cpf FROM titulares WHERE id=$1 LIMIT 1`, [titular_id]);
    if (!t.rows.length) return res.status(404).json({ ok: false, error: "Titular não encontrado." });

    const statusTitular = t.rows[0].status;
    const cpfTitular = t.rows[0].cpf;

    if (cpf && cpfTitular && cpf === cpfTitular) {
      return res.status(400).json({ ok: false, error: "CPF do dependente não pode ser igual ao CPF do titular." });
    }

    if (cpf) {
      const exists = await pool.query(
        `SELECT 1 FROM dependentes WHERE titular_id=$1 AND cpf=$2 LIMIT 1`,
        [titular_id, cpf]
      );
      if (exists.rows.length) {
        return res.status(400).json({ ok: false, error: "Já existe um dependente com esse CPF neste titular." });
      }
    }

    const r = await pool.query(
      `INSERT INTO dependentes (titular_id, nome, cpf, telefone, parentesco, data_nascimento, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, nome, cpf, telefone, parentesco, status`,
      [titular_id, nome, cpf, telefone, parentesco, data_nascimento, statusTitular]
    );

    res.json({ ok: true, dependente: r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.delete("/dependentes/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok: false, error: "ID do dependente inválido." });

    const r = await pool.query(`DELETE FROM dependentes WHERE id=$1 RETURNING id`, [id]);
    if (!r.rows.length) return res.status(404).json({ ok: false, error: "Dependente não encontrado." });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ===========================
// RELATÓRIOS | PRODUÇÃO
// - usa tabela pagamentos
// - filtro por período (de/ate) + group (dia|mes|ano)
// ===========================
app.get("/relatorios/producao", authMiddleware, requireRole("FINANCEIRO"), async (req, res) => {
  try {
    const de = String(req.query.de || "").slice(0, 10);
    const ate = String(req.query.ate || "").slice(0, 10);
    const group = String(req.query.group || "mes").toLowerCase();

    if (!de || !ate) return res.status(400).json({ ok:false, error:"Informe de e ate (YYYY-MM-DD)." });
    if (!["dia","mes","ano"].includes(group)) return res.status(400).json({ ok:false, error:"group inválido." });

    const bucket =
      group === "dia" ? "to_char(p.pago_em::date, 'YYYY-MM-DD')" :
      group === "mes" ? "to_char(date_trunc('month', p.pago_em::date), 'YYYY-MM')" :
                        "to_char(date_trunc('year', p.pago_em::date), 'YYYY')";

    const recebidoSerie = await pool.query(
      `
      SELECT ${bucket} AS periodo,
             COALESCE(SUM(p.valor),0)::numeric(12,2) AS total
      FROM pagamentos p
      WHERE upper(p.status::text) = 'PAGO'
        AND p.pago_em IS NOT NULL
        AND p.pago_em::date BETWEEN $1::date AND $2::date
      GROUP BY periodo
      ORDER BY periodo
      `,
      [de, ate]
    );

    const kpis = await pool.query(
      `
      SELECT
        COALESCE(SUM(CASE WHEN upper(status::text)='PAGO' THEN valor END),0)::numeric(12,2) AS recebido_total,
        COALESCE(SUM(CASE WHEN upper(status::text)='PENDENTE' THEN valor END),0)::numeric(12,2) AS pendente_total,

        COUNT(*) FILTER (WHERE upper(status::text)='PAGO')::int AS pagos_qtd,
        COUNT(*) FILTER (WHERE upper(status::text)='PENDENTE')::int AS pendentes_qtd,
        COUNT(*) FILTER (WHERE upper(status::text)='CANCELADO')::int AS cancelados_qtd
      FROM pagamentos
      WHERE (
        (pago_em IS NOT NULL AND pago_em::date BETWEEN $1::date AND $2::date)
        OR
        (pago_em IS NULL AND data_referencia IS NOT NULL AND data_referencia::date BETWEEN $1::date AND $2::date)
      )
      `,
      [de, ate]
    );

    const formas = await pool.query(
      `
      SELECT COALESCE(upper(p.tipo::text), 'NAO_INFORMADO') AS tipo,
            COUNT(*)::int AS qtd,
            COALESCE(SUM(p.valor),0)::numeric(12,2) AS total
      FROM pagamentos p
      WHERE upper(p.status::text)='PAGO'
        AND p.pago_em IS NOT NULL
        AND p.pago_em::date BETWEEN $1::date AND $2::date
      GROUP BY COALESCE(upper(p.tipo::text), 'NAO_INFORMADO')
      ORDER BY qtd DESC
      `,
      [de, ate]
    );

    // ✅ TITULARES: status existe e pode ser enum -> ::text
    const statusTitulares = await pool.query(
      `
      SELECT upper(t.status::text) AS status, COUNT(*)::int AS qtd
      FROM titulares t
      GROUP BY upper(t.status::text)
      ORDER BY qtd DESC
      `
    );

    const novosBucket =
      group === "dia" ? "to_char(t.criado_em::date, 'YYYY-MM-DD')" :
      group === "mes" ? "to_char(date_trunc('month', t.criado_em::date), 'YYYY-MM')" :
                        "to_char(date_trunc('year', t.criado_em::date), 'YYYY')";

    const novosConvenios = await pool.query(
      `
      SELECT ${novosBucket} AS periodo,
             COUNT(*)::int AS qtd
      FROM titulares t
      WHERE t.criado_em::date BETWEEN $1::date AND $2::date
      GROUP BY periodo
      ORDER BY periodo
      `,
      [de, ate]
    );

    const topPlanos = await pool.query(
      `
      SELECT pl.titulo,
             COUNT(*)::int AS qtd,
             COALESCE(SUM(p.valor),0)::numeric(12,2) AS total
      FROM pagamentos p
      JOIN titulares t ON t.id = p.titular_id
      JOIN planos pl ON pl.id = t.plano_id
      WHERE upper(p.status::text)='PAGO'
        AND p.pago_em IS NOT NULL
        AND p.pago_em::date BETWEEN $1::date AND $2::date
      GROUP BY pl.titulo
      ORDER BY qtd DESC
      LIMIT 10
      `,
      [de, ate]
    );

    res.json({
      ok: true,
      filtros: { de, ate, group },
      kpis: kpis.rows[0],
      recebido_serie: recebidoSerie.rows,
      formas_pagamento: formas.rows,
      status_titulares: statusTitulares.rows,
      novos_convenios: novosConvenios.rows,
      top_planos: topPlanos.rows
    });
  } catch (e) {
    console.error("ERRO /relatorios/producao:", e);
    res.status(500).json({ ok:false, error: e.message });
  }
});

// ===========================
// DASHBOARD (KPIs + séries)
// ===========================
app.get("/dashboard/resumo", authMiddleware, async (req, res) => {
  try {
    // período padrão: últimos 30 dias (para gráficos)
    const de = String(req.query.de || "").slice(0, 10);
    const ate = String(req.query.ate || "").slice(0, 10);

    const hoje = new Date();
    const ateDefault = hoje.toISOString().slice(0, 10);
    const deDate = new Date(); deDate.setDate(deDate.getDate() - 30);
    const deDefault = deDate.toISOString().slice(0, 10);

    const DE = de || deDefault;
    const ATE = ate || ateDefault;

    // ✅ KPIs Titulares (agora)
    const kTit = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE upper(status::text)='ATIVO')::int AS ativos,
        COUNT(*) FILTER (WHERE upper(status::text)='INADIMPLENTE')::int AS inadimplentes,
        COUNT(*) FILTER (WHERE upper(status::text)='CANCELADO')::int AS cancelados
      FROM titulares
    `);

    // ✅ Recebido no período (somente pagos)
    const kRec = await pool.query(
      `
      SELECT
        COALESCE(SUM(valor),0)::numeric(12,2) AS recebido,
        COUNT(*)::int AS qtd
      FROM pagamentos
      WHERE upper(status::text)='PAGO'
        AND pago_em IS NOT NULL
        AND pago_em::date BETWEEN $1::date AND $2::date
      `,
      [DE, ATE]
    );

    // ✅ Pendências no período (pelo data_referencia)
    const kPend = await pool.query(
      `
      SELECT
        COALESCE(SUM(valor),0)::numeric(12,2) AS pendente,
        COUNT(*)::int AS qtd
      FROM pagamentos
      WHERE upper(status::text)='PENDENTE'
        AND (
          (data_referencia IS NOT NULL AND data_referencia::date BETWEEN $1::date AND $2::date)
          OR (pago_em IS NOT NULL AND pago_em::date BETWEEN $1::date AND $2::date)
        )
      `,
      [DE, ATE]
    );

    // ✅ Série recebido por dia (últimos 30 dias) — PAGO
    const serieRecebido = await pool.query(
      `
      SELECT to_char(pago_em::date, 'YYYY-MM-DD') AS dia,
             COALESCE(SUM(valor),0)::numeric(12,2) AS total
      FROM pagamentos
      WHERE upper(status::text)='PAGO'
        AND pago_em IS NOT NULL
        AND pago_em::date BETWEEN $1::date AND $2::date
      GROUP BY dia
      ORDER BY dia
      `,
      [DE, ATE]
    );

    // ✅ Top planos por quantidade de titulares (agora)
    const topPlanos = await pool.query(`
      SELECT pl.titulo,
             COUNT(*)::int AS qtd
      FROM titulares t
      JOIN planos pl ON pl.id = t.plano_id
      GROUP BY pl.titulo
      ORDER BY qtd DESC
      LIMIT 6
    `);

    // ✅ Formas de pagamento (PAGO no período)
    const formas = await pool.query(
      `
      SELECT COALESCE(upper(tipo::text), 'NAO_INFORMADO') AS tipo,
             COUNT(*)::int AS qtd
      FROM pagamentos
      WHERE upper(status::text)='PAGO'
        AND pago_em IS NOT NULL
        AND pago_em::date BETWEEN $1::date AND $2::date
      GROUP BY COALESCE(upper(tipo::text), 'NAO_INFORMADO')
      ORDER BY qtd DESC
      `,
      [DE, ATE]
    );

    res.json({
      ok: true,
      periodo: { de: DE, ate: ATE },
      titulares: kTit.rows[0],
      recebido: kRec.rows[0],
      pendente: kPend.rows[0],
      serie_recebido: serieRecebido.rows,
      top_planos: topPlanos.rows,
      formas_pagamento: formas.rows
    });
  } catch (e) {
    console.error("ERRO /dashboard/resumo:", e);
    res.status(500).json({ ok:false, error: e.message });
  }
});

// ===========================
// FINANCEIRO DO TITULAR (DETALHE)
// GET /titulares/:id/financeiro
// ===========================
app.get("/titulares/:id/financeiro", authMiddleware, requireRole("ADMIN","FINANCEIRO"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok:false, error:"ID inválido." });

    const pagos = await pool.query(`
      SELECT
        id,
        tipo,
        parcelas,
        valor,
        status,
        data_referencia,
        pago_em,
        estornado_em,
        COALESCE(pago_em, estornado_em) AS data_evento,
        bandeira,
        nsu,
        autorizacao,
        criado_em
      FROM pagamentos
      WHERE titular_id = $1
      ORDER BY COALESCE(pago_em, estornado_em, criado_em) DESC, id DESC
    `, [id]);

    res.json({ ok:true, data: pagos.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error:e.message });
  }
});



// ===========================
// HISTÓRICO DE PLANOS DO TITULAR
// GET /titulares/:id/historico-planos
// ===========================
app.get(
  "/titulares/:id/historico-planos",
  authMiddleware,
  requireRole("ADMIN", "CADASTROS", "FINANCEIRO"),
  async (req, res) => {
    try {
      const titular_id = Number(req.params.id);
      if (!titular_id) return res.status(400).json({ ok: false, error: "ID inválido." });

      const r = await pool.query(
        `
        SELECT
          h.id,
          h.titular_id,
          h.plano_anterior_id,
          h.plano_novo_id,
          h.motivo,
          h.trocado_em,
          pa.titulo AS plano_anterior_titulo,
          pn.titulo AS plano_novo_titulo
        FROM titular_historico_planos h
        LEFT JOIN planos pa ON pa.id = h.plano_anterior_id
        LEFT JOIN planos pn ON pn.id = h.plano_novo_id
        WHERE h.titular_id = $1
        ORDER BY h.trocado_em DESC, h.id DESC
        `,
        [titular_id]
      );

      return res.json({ ok: true, historico: r.rows });
    } catch (e) {
      console.error("ERRO /titulares/:id/historico-planos:", e);
      return res.status(500).json({ ok: false, error: e.message });
    }
  }
);

// ===========================
// REGISTRAR PAGAMENTO DO TITULAR
// POST /titulares/:id/pagamentos
// body: { tipo, valor, parcelas?, data_referencia?, pago_em?, pix_copia?, bandeira?, nsu?, autorizacao? }
// ===========================
app.post("/titulares/:id/pagamentos", authMiddleware, requireRole("ADMIN","FINANCEIRO"), async (req, res) => {
  try {
    const titularId = Number(req.params.id);
    if (!titularId) return res.status(400).json({ ok:false, error:"ID inválido." });

    const tipo = String(req.body.tipo || "").toUpperCase().trim();
    if (!["PIX","CARTAO_AVISTA","CARTAO_12X","BOLETO"].includes(tipo)) {
      return res.status(400).json({ ok:false, error:"Tipo inválido." });
    }

    const valor = Number(req.body.valor ?? req.body.valor_total ?? 0);
    if (!(valor > 0)) return res.status(400).json({ ok:false, error:"Valor inválido." });

    // parcelas (se não vier, define)
    let parcelas = Number(req.body.parcelas || 0);
    if (!parcelas) parcelas = (tipo === "CARTAO_12X") ? 12 : 1;
    if (tipo === "BOLETO") parcelas = 3;

    // data referência (competência) - se não vier, usa hoje
    const data_referencia = (req.body.data_referencia || new Date().toISOString().slice(0,10)).slice(0,10);

    // pago_em e status
    // - se veio pago_em => status PAGO
    // - se não veio => PENDENTE
    const pago_em = req.body.pago_em ? String(req.body.pago_em).slice(0,10) : null;
    const status = pago_em ? "PAGO" : "PENDENTE";

    const pix_copia = req.body.pix_copia ? String(req.body.pix_copia).trim() : null;
    const bandeira = req.body.bandeira ? String(req.body.bandeira).trim() : null;
    const nsu = req.body.nsu ? String(req.body.nsu).trim() : null;
    const autorizacao = req.body.autorizacao ? String(req.body.autorizacao).trim() : null;

    // validações específicas
    if (tipo === "PIX" && !pix_copia && !pago_em) {
      // PIX sem comprovante e sem data de pagamento é estranho, mas deixo permitido se você quiser
      // se quiser bloquear, descomenta:
      // return res.status(400).json({ ok:false, error:"PIX precisa de pix_copia ou pago_em." });
    }

    if ((tipo === "CARTAO_AVISTA" || tipo === "CARTAO_12X") && !bandeira && !nsu && !autorizacao && !pago_em) {
      // idem: cartão pendente sem dados - deixo permitido
    }

    const r = await pool.query(
      `
      INSERT INTO pagamentos
        (titular_id, tipo, parcelas, valor, status, data_referencia, pix_copia, pago_em, bandeira, nsu, autorizacao)
      VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING id
      `,
      [titularId, tipo, parcelas, valor, status, data_referencia, pix_copia, pago_em, bandeira, nsu, autorizacao]
    );

    // ✅ opcional: se pagou, ativa o titular
    // (se você quiser essa regra automática)
    if (status === "PAGO") {
      try {
        await pool.query(`UPDATE titulares SET status='ATIVO', atualizado_em=NOW() WHERE id=$1`, [titularId]);
        await pool.query(`UPDATE dependentes SET status='ATIVO' WHERE titular_id=$1`, [titularId]);
      } catch (_) {}
    }

    res.json({ ok:true, id: r.rows[0].id });
  } catch (e) {
    console.error("ERRO POST /titulares/:id/pagamentos:", e);
    res.status(500).json({ ok:false, error:e.message });
  }
});

// ===========================
// FINANCEIRO (ITENS / A RECEBER)
// GET /financeiro/itens?q&tipo&status
// status: PENDENTE | EM_ATRASO | (vazio = todos pendentes/em atraso)
// tipo: PIX | BOLETO | CARTAO_AVISTA | CARTAO_12X
// ===========================
app.get("/financeiro/itens", authMiddleware, requireRole("ADMIN","FINANCEIRO"), async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const tipo = String(req.query.tipo || "").trim().toUpperCase();
    const status = String(req.query.status || "").trim().toUpperCase();

    const where = [];
    const params = [];

    // busca por titular
    if (q) {
      params.push(`%${q}%`);
      where.push(`(t.nome ILIKE $${params.length} OR t.cpf ILIKE $${params.length} OR t.telefone ILIKE $${params.length})`);
    }

    // filtra tipo
    if (tipo && ["PIX","BOLETO","CARTAO_AVISTA","CARTAO_12X"].includes(tipo)) {
      params.push(tipo);
      where.push(`upper(p.tipo::text) = $${params.length}`);
    }

    // por padrão: somente pendentes (inclui em atraso)
    // (a tela é "Itens pendentes e em atraso")
    where.push(`upper(p.status::text) = 'PENDENTE'`);

    // status do filtro do front (PENDENTE ou EM_ATRASO)
    if (status === "EM_ATRASO") {
      where.push(`p.data_referencia IS NOT NULL AND p.data_referencia::date < CURRENT_DATE`);
    } else if (status === "PENDENTE") {
      where.push(`(p.data_referencia IS NULL OR p.data_referencia::date >= CURRENT_DATE)`);
    } // vazio => todos pendentes (inclui atraso)

    const sql = `
      SELECT
        t.nome AS nome,
        t.cpf  AS cpf,
        upper(p.tipo::text) AS tipo,
        p.parcelas AS parcelas,
        p.valor AS valor,
        p.data_referencia AS vencimento,

        CASE
          WHEN upper(p.status::text) <> 'PENDENTE' THEN upper(p.status::text)
          WHEN p.data_referencia IS NOT NULL AND p.data_referencia::date < CURRENT_DATE THEN 'EM_ATRASO'
          ELSE 'PENDENTE'
        END AS status_calc,

        p.titular_id AS titular_id,

        -- o front usa origem para decidir qual endpoint chamar no "baixar"
        -- como estamos tratando tudo como pagamentos, origem diferente de BOLETO cai no endpoint /pagamentos/:id/marcar-pago
        'PAGAMENTOS' AS origem,

        -- o front chama isso de item_id
        p.id AS item_id
      FROM pagamentos p
      JOIN titulares t ON t.id = p.titular_id
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY COALESCE(p.data_referencia, p.criado_em)::date ASC, p.id DESC
      LIMIT 1000
    `;

    const r = await pool.query(sql, params);
    return res.json({ ok: true, itens: r.rows });
  } catch (e) {
    console.error("ERRO /financeiro/itens:", e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// ===========================
// MARCAR PAGAMENTO COMO PAGO
// POST /pagamentos/:id/marcar-pago
// body: { pago_em: "YYYY-MM-DD" }
// ===========================
app.post("/pagamentos/:id/marcar-pago", authMiddleware, requireRole("ADMIN","FINANCEIRO"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok:false, error:"ID inválido." });

    const pago_em = req.body.pago_em ? String(req.body.pago_em).slice(0,10) : null;
    if (!pago_em) return res.status(400).json({ ok:false, error:"pago_em é obrigatório (YYYY-MM-DD)." });

    // pega o titular do pagamento
    const p = await pool.query(`SELECT id, titular_id FROM pagamentos WHERE id=$1 LIMIT 1`, [id]);
    if (!p.rows.length) return res.status(404).json({ ok:false, error:"Pagamento não encontrado." });

    const titularId = Number(p.rows[0].titular_id || 0);

    // marca pagamento como PAGO
    await pool.query(
      `UPDATE pagamentos SET status='PAGO', pago_em=$1 WHERE id=$2`,
      [pago_em, id]
    );

    // ✅ ATIVA titular e dependentes
    if (titularId) {
      await pool.query(`UPDATE titulares SET status='ATIVO', atualizado_em=NOW() WHERE id=$1`, [titularId]);
      await pool.query(`UPDATE dependentes SET status='ATIVO' WHERE titular_id=$1`, [titularId]);
    }

    return res.json({ ok:true, id });
  } catch (e) {
    console.error("ERRO /pagamentos/:id/marcar-pago:", e);
    return res.status(500).json({ ok:false, error:e.message });
  }
});


// ===========================
// ESTORNAR PAGAMENTO
// POST /pagamentos/:id/estornar
// body: { motivo?: string }
// Regras:
// - Se estava PAGO -> volta para PENDENTE e remove pago_em
// - Se quiser, você pode marcar como CANCELADO em vez de PENDENTE (ajusto se preferir)
// ===========================
app.post("/pagamentos/:id/estornar", authMiddleware, requireRole("ADMIN","FINANCEIRO"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ ok:false, error:"ID inválido." });

    const hoje = new Date().toISOString().slice(0, 10);

    const r = await pool.query(
      `
      UPDATE pagamentos
      SET status = 'ESTORNADO',
          pago_em = NULL,
          estornado_em = $1
      WHERE id = $2
      RETURNING id
      `,
      [hoje, id]
    );

    if (!r.rows.length) return res.status(404).json({ ok:false, error:"Pagamento não encontrado." });

    return res.json({ ok:true, id: r.rows[0].id });
  } catch (e) {
    console.error("ERRO /pagamentos/:id/estornar:", e);
    return res.status(500).json({ ok:false, error:e.message });
  }
});



/* ===========================
   (As rotas de FINANCEIRO e INADIMPLÊNCIA)
   -> mantenha como você já tem, estão OK.
   =========================== */

app.listen(PORT, () => {
  console.log("API rodando em http://127.0.0.1:" + PORT);
});




