const express = require("express");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const app = express();
const privateKey = fs.readFileSync("private.pem");
const publicKey = fs.readFileSync("public.pem");

// Issues a legit RS256 token
app.get("/login", (req, res) => {
  const token = jwt.sign({ username: "pom" }, privateKey, {
    algorithm: "RS256",
  });
  res.json({ token });
});

// VULNERABLE: old jsonwebtoken doesn't detect PEM key misuse for HS256
app.get("/profile", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "no token provided" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ["RS256", "HS256"],
    });
    res.json({ message: `Welcome, ${decoded.username}`, data: decoded });
  } catch (err) {
    res.status(403).json({ error: "invalid or expired token: " + err.message });
  }
});

app.listen(4000, () =>
  console.log("Legacy vulnerable server running on http://localhost:4000"),
);
