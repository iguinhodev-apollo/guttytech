/**
 * server.js — GuttyTECH
 * - Express + MongoDB (Mongoose)
 * - Admin login (JWT) + CRUD básico de posts
 * - Static site (/public)
 * - Fallback SPA-like (volta pro index.html) + páginas 404 amigáveis
 * - Hardening de segurança (Helmet, rate-limit, CORS, headers, limits)
 */

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");

const app = express();

/* =========================
   Config / Safety checks
========================= */
function mustEnv(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) {
    console.error(`❌ Falta variável no .env: ${name}`);
    process.exit(1);
  }
  return v;
}

const MONGO_URI = mustEnv("MONGO_URI");
const JWT_SECRET = mustEnv("JWT_SECRET");
const ADMIN_USER = mustEnv("ADMIN_USER");
const ADMIN_PASSWORD_HASH = mustEnv("ADMIN_PASSWORD_HASH");

app.disable("x-powered-by");
app.set("trust proxy", 1);

const PUBLIC_DIR = path.join(__dirname, "public");

/* =========================
   Security / Hardening
========================= */

// Helmet: headers de segurança (CSP ajustado para seu front com Google Fonts + Remixicon CDN)
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }, // permite imagens externas se precisar
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        // Seu front usa CSS inline e possivelmente scripts inline
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net", "data:"],
        imgSrc: ["'self'", "data:", "https:"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: null, // não força se você estiver testando local
      },
    },
  })
);

// CORS (opcional): por padrão só libera o próprio domínio.
// Se você consumir API de outro domínio, coloque CORS_ORIGIN no .env (ex: https://guttytech.com.br)
const CORS_ORIGIN = (process.env.CORS_ORIGIN || "").trim();
app.use(
  cors(
    CORS_ORIGIN
      ? {
          origin: CORS_ORIGIN.split(",").map((s) => s.trim()),
          methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
          allowedHeaders: ["Content-Type", "Authorization"],
          credentials: false,
          maxAge: 86400,
        }
      : {
          origin: false, // bloqueia cross-site por padrão
        }
  )
);

// Rate limit geral (API)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api", apiLimiter);

// Rate limit mais forte no login (anti brute-force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/admin/login", loginLimiter);

// Body limit
app.use(express.json({ limit: "1mb", strict: true }));

/* =========================
   Static files
========================= */
app.use(
  express.static(PUBLIC_DIR, {
    extensions: ["html"],
    etag: true,
    maxAge: "1h",
    setHeaders(res) {
      // evita mime sniffing
      res.setHeader("X-Content-Type-Options", "nosniff");
    },
  })
);

/* =========================
   MongoDB (Mongoose)
========================= */
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Conectado ao MongoDB"))
  .catch((err) => {
    console.error("❌ Erro ao conectar ao MongoDB:", err.message);
    process.exit(1);
  });

/* =========================
   Model: Post
========================= */
const PostSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 140 },
    slug: { type: String, required: true, unique: true, trim: true, maxlength: 140 },
    excerpt: { type: String, required: true, trim: true, maxlength: 240 },
    content: { type: String, required: true, trim: true, maxlength: 200000 }, // HTML
    coverImage: { type: String, trim: true, default: "" },
    author: { type: String, trim: true, default: "GuttyTECH" },
  },
  { timestamps: true }
);

PostSchema.index({ slug: 1 }, { unique: true });

const Post = mongoose.model("Post", PostSchema);

/* =========================
   Helpers
========================= */
function safeSlug(input) {
  return String(input || "")
    .toLowerCase()
    .trim()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function isHtmlString(s) {
  // “mínimo” pra evitar lixo / payloads estranhos
  const str = String(s || "");
  return str.length > 0 && str.length <= 200000;
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Sem token" });

  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
}

// handler async seguro (evita try/catch repetido)
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/* =========================
   ADMIN
========================= */
app.post(
  "/admin/login",
  asyncHandler(async (req, res) => {
    const { user, password } = req.body || {};
    if (!user || !password) return res.status(400).json({ error: "Informe usuário e senha" });

    // evita timing attacks simples
    if (String(user) !== String(ADMIN_USER)) {
      await new Promise((r) => setTimeout(r, 150));
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const ok = await bcrypt.compare(String(password), String(ADMIN_PASSWORD_HASH));
    if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });

    const token = jwt.sign({ user }, JWT_SECRET, {
      expiresIn: "2h",
      issuer: "guttytech",
      audience: "guttytech-admin",
    });

    return res.json({ token });
  })
);

// Criar post
app.post(
  "/admin/posts",
  auth,
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const title = String(body.title || "").trim();
    const excerpt = String(body.excerpt || "").trim();
    const content = String(body.content || "").trim();
    const coverImage = String(body.coverImage || "").trim();
    const slug = safeSlug(body.slug || title);

    if (!title || !excerpt || !content) {
      return res.status(400).json({ error: "Campos obrigatórios: title, excerpt, content" });
    }
    if (!slug) return res.status(400).json({ error: "Slug inválido" });
    if (!isHtmlString(content)) return res.status(400).json({ error: "Content inválido" });

    const created = await Post.create({
      title,
      excerpt,
      content,
      coverImage,
      slug,
      author: "GuttyTECH",
    });

    return res.status(201).json(created);
  })
);

// Atualizar post
app.put(
  "/admin/posts/:slug",
  auth,
  asyncHandler(async (req, res) => {
    const slug = safeSlug(req.params.slug);
    const body = req.body || {};

    const update = {};
    if (body.title != null) update.title = String(body.title).trim();
    if (body.excerpt != null) update.excerpt = String(body.excerpt).trim();
    if (body.content != null) update.content = String(body.content).trim();
    if (body.coverImage != null) update.coverImage = String(body.coverImage).trim();

    if (update.content && !isHtmlString(update.content)) {
      return res.status(400).json({ error: "Content inválido" });
    }

    const updated = await Post.findOneAndUpdate({ slug }, update, { new: true });
    if (!updated) return res.status(404).json({ error: "Post não encontrado" });
    return res.json(updated);
  })
);

// Deletar post
app.delete(
  "/admin/posts/:slug",
  auth,
  asyncHandler(async (req, res) => {
    const slug = safeSlug(req.params.slug);
    const deleted = await Post.findOneAndDelete({ slug });
    if (!deleted) return res.status(404).json({ error: "Post não encontrado" });
    return res.json({ ok: true });
  })
);

/* =========================
   PUBLIC API
========================= */
// Lista posts (sem content)
app.get(
  "/api/posts",
  asyncHandler(async (_req, res) => {
    const posts = await Post.find({}, { content: 0 }).sort({ createdAt: -1 }).lean();
    res.json(posts);
  })
);

// Busca 1 post por slug
app.get(
  "/api/posts/:slug",
  asyncHandler(async (req, res) => {
    const slug = safeSlug(req.params.slug);
    const post = await Post.findOne({ slug }).lean();
    if (!post) return res.status(404).json({ error: "Post não encontrado" });
    res.json(post);
  })
);

/* =========================
   404 / Cannot GET /... (API e Admin)
========================= */
app.use("/api", (_req, res) => {
  res.status(404).json({ error: "Rota da API não encontrada" });
});

app.use("/admin", (req, res) => {
  // se tentar acessar /admin no navegador, redireciona pra home
  if (req.method === "GET") return res.redirect(302, "/");
  return res.status(404).json({ error: "Rota admin não encontrada" });
});

/* =========================
   Fallback do site (sem /api e sem /admin)
   - Se existir arquivo real -> serve
   - Se não existir -> volta pro index.html (evita "Cannot GET")
========================= */
app.get(/^(?!\/api\/|\/admin\/).*/, (req, res) => {
  const reqPath = req.path === "/" ? "/index.html" : req.path;
  const filePath = path.join(PUBLIC_DIR, reqPath);

  res.sendFile(filePath, (err) => {
    if (err) return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  });
});

/* =========================
   Error handler final
========================= */
app.use((err, req, res, _next) => {
  console.error("❌ Erro:", err?.message || err);

  // erros comuns do JSON
  if (err?.type === "entity.parse.failed") {
    return res.status(400).json({ error: "JSON inválido" });
  }

  // se for request de API/ADMIN, responde JSON
  if (req.path.startsWith("/api") || req.path.startsWith("/admin")) {
    return res.status(500).json({ error: "Erro interno" });
  }

  // para o site, volta pro index.html (evita tela de erro feia)
  return res.status(302).redirect("/");
});

/* =========================
   Start + Shutdown clean
========================= */
const PORT = Number(process.env.PORT || 3000);
const server = app.listen(PORT, () => console.log(`🚀 Servidor rodando em http://localhost:${PORT}`));

function shutdown(signal) {
  console.log(`\n🛑 Recebido ${signal}. Encerrando...`);
  server.close(() => {
    mongoose.connection.close(false).then(() => {
      console.log("✅ Encerrado com segurança.");
      process.exit(0);
    });
  });
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
