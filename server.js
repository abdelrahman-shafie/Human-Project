const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json());

/*****************************************************************
 *  SECTION 1: JWT AUTHENTICATION
 *****************************************************************/

// In-memory users (for JWT)
const users = [{ id: 1, username: "user1", password: "pass1" }];

// JWT secret
const JWT_SECRET = "super_secret_jwt_key_change_me";

// POST /login (JWT)
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const user = users.find(
    (u) => u.username === username && u.password === password
  );
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1h" });
  return res.json({ token });
});

// JWT middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Authorization header missing" });
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res
      .status(401)
      .json({ error: "Invalid Authorization header format" });
  }

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { userId: payload.userId };
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Protected route (JWT)
app.get("/profile", authMiddleware, (req, res) => {
  return res.json({ message: "JWT Authenticated", userId: req.user.userId });
});

/*****************************************************************
 *  SECTION 2: OAUTH2 (LOCAL PROVIDER)
 *****************************************************************/

// In-memory OAuth data
const OAUTH_CLIENTS = [
  {
    id: "client123",
    secret: "secret123",
    redirectUri: "http://localhost:3000/callback",
  },
];

const OAUTH_USERS = [{ id: 1, username: "oauthUser", password: "oauthPass" }];

// Storage for auth codes + tokens
const authCodes = {};
const accessTokens = {};

// GET /oauth/authorize
app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri } = req.query;

  const client = OAUTH_CLIENTS.find((c) => c.id === client_id);
  if (!client || client.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: "Invalid client_id or redirect_uri" });
  }

  res.json({
    message: "Send username & password via POST /oauth/login",
    client_id,
    redirect_uri,
  });
});

// POST /oauth/login (generate code)
app.post("/oauth/login", (req, res) => {
  const { username, password, client_id, redirect_uri } = req.body;

  const user = OAUTH_USERS.find(
    (u) => u.username === username && u.password === password
  );
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const code = crypto.randomBytes(16).toString("hex");
  authCodes[code] = { userId: user.id };

  return res.json({
    message: "Authorization successful",
    code,
    redirect_uri,
  });
});

// POST /oauth/token
app.post("/oauth/token", (req, res) => {
  const { code, client_id, client_secret } = req.body;

  const validClient = OAUTH_CLIENTS.find(
    (c) => c.id === client_id && c.secret === client_secret
  );
  if (!validClient) return res.status(401).json({ error: "Invalid client" });

  if (!authCodes[code]) return res.status(400).json({ error: "Invalid code" });

  const token = crypto.randomBytes(32).toString("hex");
  accessTokens[token] = { userId: authCodes[code].userId };

  delete authCodes[code]; // one-time use

  return res.json({
    access_token: token,
    token_type: "Bearer",
    expires_in: 3600,
  });
});

// Protected route (OAuth)
app.get("/oauth/profile", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ error: "Missing Authorization header" });

  const [type, token] = auth.split(" ");
  if (type !== "Bearer" || !accessTokens[token]) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  res.json({
    message: "OAuth Authenticated",
    userId: accessTokens[token].userId,
  });
});

/*****************************************************************
 *  SECTION 3: API KEY AUTHENTICATION
 *****************************************************************/

// Static API Key (just for demo)
const VALID_API_KEY = "my_super_secret_api_key";

// Middleware
function apiKeyMiddleware(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return res.status(401).json({ error: "API key missing" });
  }

  if (apiKey !== VALID_API_KEY) {
    return res.status(403).json({ error: "Invalid API key" });
  }

  next();
}

// Protected route (API Key)
app.get("/apikey/data", apiKeyMiddleware, (req, res) => {
  res.json({
    message: "API Key Authenticated",
    data: { secret: "Here is protected data." },
  });
});

/*****************************************************************
 *  SECTION 4: HEALTH CHECK
 *****************************************************************/

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

/*****************************************************************
 *  START SERVER
 *****************************************************************/

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
