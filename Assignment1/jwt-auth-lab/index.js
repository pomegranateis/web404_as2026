require("dotenv").config();

const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const fs = require("fs");

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error(
    "FATAL: JWT_SECRET is not set in environment. Refusing to start.",
  );
  process.exit(1);
}

const privateKey = fs.readFileSync("private.pem");
const publicKey = fs.readFileSync("public.pem");

// In-memory "database"
const users = [];

// Signup
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }

  const existing = users.find((u) => u.username === username);
  if (existing) {
    return res.status(409).json({ error: "user already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: "user created" });
});

const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // limit each IP to 5 login attempts per window
  message: { error: "Too many login attempts. Please try again in 5 minutes." },
  standardHeaders: true, // return rate limit info in RateLimit-* headers
  legacyHeaders: false,
});

// Login — SECURE: strong secret (env-loaded), pinned algorithm, short expiry, httpOnly cookie
app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  const token = jwt.sign({ username: user.username }, JWT_SECRET, {
    algorithm: "HS256", // explicitly pin the algorithm
    expiresIn: "15m", // short-lived token
  });

  res.cookie("token", token, {
    httpOnly: true, // JavaScript cannot read this cookie — blocks XSS token theft
    secure: false, // set to true in production (requires HTTPS)
    sameSite: "strict", // blocks the cookie being sent on cross-site requests (CSRF mitigation)
    maxAge: 15 * 60 * 1000, // 15 minutes, matches token expiry
  });

  res.json({ message: "login successful" });
});

// Protected route — SECURE: reads token from httpOnly cookie, algorithm pinned on verify
app.get("/profile", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "no token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"], // reject any other algorithm, even if attacker specifies one
    });
    res.json({ message: `Welcome, ${decoded.username}`, data: decoded });
  } catch (err) {
    res.status(403).json({ error: "invalid or expired token" });
  }
});

// ─────────────────────────────────────────────
// VULNERABLE ROUTES — kept intentionally for attack-phase demonstration
// DO NOT use these patterns in production
// ─────────────────────────────────────────────

// VULNERABLE: verifies without restricting algorithms
app.get("/profile-vulnerable", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "no token provided" });

  const token = authHeader.split(" ")[1];

  try {
    const decodedHeader = jwt.decode(token, { complete: true }).header;

    let decoded;
    if (decodedHeader.alg === "none") {
      decoded = jwt.decode(token);
    } else {
      decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: [decodedHeader.alg],
      });
    }

    res.json({
      message: `Welcome, ${decoded.username}`,
      data: decoded,
      note: "via vulnerable endpoint",
    });
  } catch (err) {
    res.status(403).json({ error: "invalid or expired token" });
  }
});

// Issues a token signed with RS256 (private key)
app.get("/login-rs256", (req, res) => {
  const token = jwt.sign({ username: "pom" }, privateKey, {
    algorithm: "RS256",
  });
  res.json({ token });
});

// Simulates a public endpoint exposing the public key (like a JWKS endpoint)
app.get("/public-key", (req, res) => {
  res.type("text/plain").send(publicKey.toString());
});

// VULNERABLE: verifies without pinning algorithm
app.get("/profile-rs256-vulnerable", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "no token provided" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, publicKey);
    res.json({
      message: `Welcome, ${decoded.username}`,
      data: decoded,
      note: "via RS256 vulnerable endpoint",
    });
  } catch (err) {
    res.status(403).json({ error: "invalid or expired token: " + err.message });
  }
});

// VULNERABLE: explicitly whitelists both algorithms
app.get("/profile-alg-confusion", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "no token provided" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ["RS256", "HS256"],
    });
    res.json({
      message: `Welcome, ${decoded.username}`,
      data: decoded,
      note: "via alg-confusion vulnerable endpoint",
    });
  } catch (err) {
    res.status(403).json({ error: "invalid or expired token: " + err.message });
  }
});

// SECURE: RS256 only — no algorithm confusion possible
app.get("/profile-rs256-secure", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "no token provided" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ["RS256"], // ONLY RS256 — HS256 can never be used, even if attacker tries
    });
    res.json({
      message: `Welcome, ${decoded.username}`,
      data: decoded,
      note: "via secure RS256 endpoint",
    });
  } catch (err) {
    res.status(403).json({ error: "invalid or expired token: " + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
