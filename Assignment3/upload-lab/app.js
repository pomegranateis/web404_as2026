// app.js — File Upload Security lab (WEB404 Assignment 3)
//
// One Express server exposing a VULNERABLE and a SECURE upload endpoint so the
// report can show a direct before/after comparison.
//
//   VULNERABLE:
//     POST /upload-vulnerable   -> accepts ANY file, keeps the attacker's filename,
//                                  stores it in a publicly-served directory.
//     GET  /files/<name>        -> serves the vulnerable uploads as static files
//                                  (so an uploaded .html/.svg executes in the browser).
//
//   SECURE:
//     POST /upload-secure       -> extension + MIME allowlist, magic-byte check,
//                                  size limit, random filename, stored OUTSIDE webroot.
//     GET  /download/:id        -> serves secure uploads via a controlled handler
//                                  that forces a safe Content-Type + attachment.
//
// Run:  node app.js    ->  http://localhost:3002

const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = 3002;

const VULN_DIR = path.join(__dirname, "uploads-vulnerable");
const SECURE_DIR = path.join(__dirname, "uploads-secure"); // NOT served statically
fs.mkdirSync(VULN_DIR, { recursive: true });
fs.mkdirSync(SECURE_DIR, { recursive: true });

// ───────────────────────────────────────────────────────────────────────────
// VULNERABLE UPLOAD  — DO NOT COPY
// Keeps the client-supplied filename and drops the file into a public directory.
// ───────────────────────────────────────────────────────────────────────────
const vulnStorage = multer.diskStorage({
  destination: VULN_DIR,
  // BUG: trusts req.file.originalname verbatim -> path traversal + dangerous extensions.
  filename: (req, file, cb) => cb(null, file.originalname),
});
const vulnUpload = multer({ storage: vulnStorage }); // no fileFilter, no limits

app.post("/upload-vulnerable", vulnUpload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "no file" });
  res.json({
    stored_as: req.file.filename,
    served_at: `/files/${req.file.filename}`,
    size: req.file.size,
    client_content_type: req.file.mimetype, // trusted blindly — spoofable
  });
});

// Serves the vulnerable upload directory as static files, with whatever
// Content-Type the extension implies -> uploaded HTML/SVG runs as active content.
app.use("/files", express.static(VULN_DIR));

// ───────────────────────────────────────────────────────────────────────────
// SECURE UPLOAD — the fix.
// ───────────────────────────────────────────────────────────────────────────

// Allowlist of permitted image types: extension + declared MIME + magic bytes.
const ALLOWED = {
  "image/png": { ext: ".png", magic: [0x89, 0x50, 0x4e, 0x47] }, // \x89PNG
  "image/jpeg": { ext: ".jpg", magic: [0xff, 0xd8, 0xff] }, // JPEG SOI
  "image/gif": { ext: ".gif", magic: [0x47, 0x49, 0x46, 0x38] }, // GIF8
};
const MAX_BYTES = 1 * 1024 * 1024; // 1 MB

// Store in memory so we can inspect the real bytes before writing anything to disk.
const secureUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BYTES, files: 1 },
  fileFilter: (req, file, cb) => {
    // First gate: the declared MIME must be in the allowlist and the extension must match.
    const rule = ALLOWED[file.mimetype];
    if (!rule) return cb(null, false);
    if (path.extname(file.originalname).toLowerCase() !== rule.ext &&
        !(rule.ext === ".jpg" && path.extname(file.originalname).toLowerCase() === ".jpeg")) {
      return cb(null, false);
    }
    cb(null, true);
  },
});

function magicMatches(buf, magic) {
  if (buf.length < magic.length) return false;
  return magic.every((b, i) => buf[i] === b);
}

// in-memory index mapping a random id -> stored file metadata
const secureFiles = new Map();

app.post("/upload-secure", (req, res) => {
  secureUpload.single("file")(req, res, (err) => {
    // multer surfaces the size-limit breach here as an error.
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) {
      return res.status(400).json({ error: "rejected: type not allowed (png/jpg/gif only)" });
    }

    const rule = ALLOWED[req.file.mimetype];

    // Second gate: verify the real content via magic bytes — defeats MIME/extension spoofing.
    if (!magicMatches(req.file.buffer, rule.magic)) {
      return res.status(400).json({ error: "rejected: file content does not match its type" });
    }

    // Generate our OWN random filename — never trust the client's.
    const id = crypto.randomUUID();
    const safeName = id + rule.ext;
    const dest = path.join(SECURE_DIR, safeName);

    // Extra belt-and-braces: ensure the resolved path stays inside SECURE_DIR.
    if (path.dirname(path.resolve(dest)) !== path.resolve(SECURE_DIR)) {
      return res.status(400).json({ error: "path check failed" });
    }

    fs.writeFileSync(dest, req.file.buffer);
    secureFiles.set(id, { name: safeName, type: req.file.mimetype });

    res.json({
      id,
      stored_as: safeName,            // random — not attacker-controlled
      download_at: `/download/${id}`, // served via a controlled handler, not statically
      size: req.file.size,
      verified_type: req.file.mimetype,
    });
  });
});

// Controlled download: looks the file up by id, sets a safe Content-Type, and
// forces download instead of inline rendering (neutralises any active content).
app.get("/download/:id", (req, res) => {
  const meta = secureFiles.get(req.params.id);
  if (!meta) return res.status(404).json({ error: "not found" });

  res.setHeader("Content-Type", meta.type);
  res.setHeader("Content-Disposition", `attachment; filename="${meta.name}"`);
  res.setHeader("X-Content-Type-Options", "nosniff"); // stop browser MIME-sniffing
  res.sendFile(path.join(SECURE_DIR, meta.name));
});

// Minimal upload form for manual testing.
app.get("/", (req, res) => {
  res.type("html").send(`<!doctype html><meta charset=utf-8><h2>Upload lab</h2>
  <form method=post enctype=multipart/form-data action=/upload-vulnerable>
    vulnerable: <input type=file name=file><button>upload</button></form>
  <form method=post enctype=multipart/form-data action=/upload-secure>
    secure: <input type=file name=file><button>upload</button></form>`);
});

app.listen(PORT, () => console.log(`Upload lab running on http://localhost:${PORT}`));
