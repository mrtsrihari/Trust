// server.js
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import { Block, certificateChain, hashData } from "./blockchain.js";
import multer from "multer";
import csv from "csv-parser";
import fs from "fs";
import path from "path";
import crypto from "crypto";

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

// ------------------ AES-256 Encryption ------------------
const SECRET_KEY = process.env.ENCRYPTION_KEY
  ? Buffer.from(process.env.ENCRYPTION_KEY, "hex")
  : crypto.randomBytes(32); // fallback for dev
const IV_LENGTH = 16;

function encrypt(text) {
  if (text === null || text === undefined) return null;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, iv);
  let encrypted = cipher.update(String(text), "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(encryptedText) {
  if (!encryptedText) return null;
  const parts = String(encryptedText).split(":");
  if (parts.length !== 2) return null;
  const [ivHex, encrypted] = parts;
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
// --------------------------------------------------------

// Date parser
function parseDate(dobStr) {
  const date = new Date(dobStr);
  if (isNaN(date)) throw new Error(`Invalid DOB format: ${dobStr}`);
  return date;
}

// CORS
app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001"],
    credentials: true,
  })
);

// File uploads
const upload = multer({ dest: "uploads/" });

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key";

// ------------------ Middleware ------------------
function authMiddleware(role) {
  return (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).json({ error: "No token provided" });

      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.status(403).json({ error: "Forbidden" });

      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

// ------------------ Routes ------------------

app.get("/", (req, res) => res.json({ ok: true, msg: "Backend Running Successfully" }));

// ---------------- Admin ----------------
app.post("/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin) return res.status(404).json({ error: "Admin not found" });

    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: admin.id, email: admin.email, role: "admin" }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error("admin/login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/admin/colleges", authMiddleware("admin"), async (req, res) => {
  try {
    const colleges = await prisma.college.findMany();
    res.json(colleges);
  } catch (err) {
    console.error("admin/colleges error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/admin/add-college", authMiddleware("admin"), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

    const hashed = await bcrypt.hash(password, 10);
    const college = await prisma.college.create({ data: { name, email, password: hashed } });
    res.json({ message: "College added", college });
  } catch (err) {
    console.error("admin/add-college error:", err);
    res.status(500).json({ error: "Error adding college" });
  }
});

// ---------------- College auth ----------------
app.post("/college/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const college = await prisma.college.findUnique({ where: { email } });
    if (!college) return res.status(404).json({ error: "College not found" });

    const match = await bcrypt.compare(password, college.password);
    if (!match) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: college.id, name: college.name, role: "college" }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, name: college.name });
  } catch (err) {
    console.error("college/login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- College endpoints ----------------
app.get("/college/course-summary", authMiddleware("college"), async (req, res) => {
  try {
    const certs = await prisma.certificate.findMany({ where: { collegeId: req.user.id } });
    const summary = certs.reduce((acc, c) => {
      const course = decrypt(c.course);
      if (course && course.trim()) acc[course] = (acc[course] || 0) + 1;
      return acc;
    }, {});
    res.json(Object.entries(summary).map(([course, count]) => ({ course, count })));
  } catch (err) {
    console.error("course-summary error:", err);
    res.status(500).json({ error: "Failed to get course summary" });
  }
});

app.get("/college/my-certificates", authMiddleware("college"), async (req, res) => {
  try {
    const certs = await prisma.certificate.findMany({
      where: { collegeId: req.user.id },
      include: { college: true },
      orderBy: { createdAt: "desc" },
    });

    const decrypted = certs.map((c) => ({
      certificateId: c.certificateId,
      studentName: decrypt(c.studentName),
      email: c.email ? decrypt(c.email) : null,
      course: decrypt(c.course),
      adharEncrypted: c.adharEncrypted ? decrypt(c.adharEncrypted) : null,
      adharHash: c.adharHash,
      rollNo: c.rollNo,
      collegeName: c.college?.name || null,
      link: c.link ? decrypt(c.link) : null,
      dob: c.dob,
      blockchainHash: c.blockchainHash,
      createdAt: c.createdAt,
    }));

    res.json(decrypted);
  } catch (err) {
    console.error("my-certificates error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- CSV upload ----------------
app.post("/college/upload-csv", authMiddleware("college"), upload.single("file"), async (req, res) => {
  try {
    // debug: ensure req.user is college
    // console.log("CSV upload token user:", req.user);

    // validate college exists
    const collegeExists = await prisma.college.findUnique({ where: { id: req.user.id } });
    if (!collegeExists) return res.status(400).json({ error: "Invalid college token or college not found" });

    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const filePath = path.join(process.cwd(), req.file.path);
    const rows = [];

    fs.createReadStream(filePath)
      .pipe(csv())
      .on("data", (row) => {
        const studentName = row.studentName || row.name;
        const email = row.email;
        const dob = row.dob;
        const course = row.course;
        const rollNo = row.rollNo || row.rollno;
        const adharNumber = row.adharNumber || row.aadhar;
        const link = row.link;

        if (!studentName || !email || !dob || !course || !adharNumber || !rollNo) {
          console.warn("Skipping row due to missing data:", row);
          return;
        }

        rows.push({ studentName, email, dob, course, rollNo, adharNumber, link });
      })
      .on("end", async () => {
        try { fs.unlinkSync(filePath); } catch (e) { /* ignore */ }

        const inserted = [];
        for (const r of rows) {
          try {
            const count = await prisma.certificate.count();
            const certificateId = `Trust${2000 + count + 1}`;

            const encryptedName = encrypt(r.studentName);
            const encryptedEmail = encrypt(r.email);
            const encryptedCourse = encrypt(r.course);
            const encryptedLink = r.link ? encrypt(r.link) : null;
            const adharHash = hashData(r.adharNumber);
            const adharEncrypted = encrypt(r.adharNumber);
            const emailHash = hashData(r.email);

            const blockchainHash = certificateChain.addBlock(
              new Block(certificateChain.chain.length, Date.now().toString(), {
                certificateId,
                studentName: r.studentName,
                email: r.email,
                dob: new Date(r.dob).toISOString(),
                course: r.course,
                adharHash,
                rollNo: r.rollNo,
                college: req.user.name,
              })
            );

            const cert = await prisma.certificate.create({
              data: {
                certificateId,
                studentName: encryptedName,
                email: encryptedEmail,
                emailHash,
                dob: new Date(r.dob),
                course: encryptedCourse,
                adharHash,
                adharEncrypted,
                blockchainHash,
                rollNo: r.rollNo,
                collegeId: req.user.id,
                link: encryptedLink,
              },
            });

            inserted.push(cert);
          } catch (err) {
            console.error("Insert error:", err.message || err);
          }
        }

        res.json({ message: "CSV processed", insertedCount: inserted.length });
      })
      .on("error", (err) => {
        console.error("CSV parse error:", err);
        res.status(500).json({ error: "CSV processing failed" });
      });
  } catch (err) {
    console.error("upload-csv error:", err);
    res.status(500).json({ error: "Server error during upload" });
  }
});

// ---------------- Update certificate (MISSING ROUTE fixed) ----------------
app.put("/college/update-certificate/:certificateId", authMiddleware("college"), async (req, res) => {
  try {
    const { certificateId } = req.params;
    const { studentName, email, course, dob, rollNo, adharNumber } = req.body;

    const cert = await prisma.certificate.findUnique({ where: { certificateId } });
    if (!cert) return res.status(404).json({ error: "Certificate not found" });

    // Build blockchain entry using existing or new values
    const updatedBlockHash = certificateChain.addBlock(
      new Block(certificateChain.chain.length, Date.now().toString(), {
        certificateId,
        studentName: studentName || decrypt(cert.studentName),
        email: email || (cert.email ? decrypt(cert.email) : null),
        dob: dob ? parseDate(dob).toISOString() : cert.dob.toISOString(),
        course: course || decrypt(cert.course),
        adharHash: adharNumber ? hashData(adharNumber) : cert.adharHash,
        rollNo: rollNo || cert.rollNo,
        college: req.user.name,
      })
    );

    const updatedData = {
      studentName: studentName ? encrypt(studentName) : cert.studentName,
      email: email ? encrypt(email) : cert.email,
      course: course ? encrypt(course) : cert.course,
      dob: dob ? parseDate(dob) : cert.dob,
      rollNo: rollNo || cert.rollNo,
      blockchainHash: updatedBlockHash,
    };

    if (email) updatedData.emailHash = hashData(email);
    if (adharNumber) {
      updatedData.adharHash = hashData(adharNumber);
      updatedData.adharEncrypted = encrypt(adharNumber);
    }

    const updatedCert = await prisma.certificate.update({
      where: { certificateId },
      data: updatedData,
    });

    res.json({ message: "Certificate updated", updatedCert });
  } catch (err) {
    console.error("update-certificate error:", err);
    res.status(500).json({ error: "Failed to update certificate" });
  }
});

// ---------------- Search ----------------
app.post("/search-certificates", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const emailHash = hashData(email);
    const matches = await prisma.certificate.findMany({
      where: { emailHash },
      include: { college: true },
      orderBy: { createdAt: "desc" },
    });

    if (!matches.length) return res.json({ certificates: [] });

    const result = matches.map((c) => ({
      certificateId: c.certificateId,
      studentName: decrypt(c.studentName),
      email: c.email ? decrypt(c.email) : null,
      dob: c.dob,
      course: decrypt(c.course),
      rollNo: c.rollNo,
      collegeName: c.college?.name || null,
      adharEncrypted: c.adharEncrypted ? decrypt(c.adharEncrypted) : null,
      link: c.link ? decrypt(c.link) : null,
      blockchainHash: c.blockchainHash,
      createdAt: c.createdAt,
    }));

    res.json({ certificates: result });
  } catch (err) {
    console.error("search-certificates error:", err);
    res.status(500).json({ error: "Search failed" });
  }
});

// ---------------- Verify ----------------
app.post("/verify-certificate", async (req, res) => {
  try {
    const { certificateId, adharNumber } = req.body;
    if (!certificateId || !adharNumber) return res.status(400).json({ error: "Certificate ID and Aadhaar required" });

    const cert = await prisma.certificate.findUnique({ where: { certificateId }, include: { college: true } });
    if (!cert) return res.status(404).json({ error: "Certificate not found" });

    const adharMatch = cert.adharHash === hashData(adharNumber);
    const chainValid = certificateChain.isChainValid();
    const block = certificateChain.findBlockByHash(cert.blockchainHash);

    let dataMatch = false;
    if (block) {
      const b = block.data;
      dataMatch =
        b.certificateId === cert.certificateId &&
        b.studentName === decrypt(cert.studentName) &&
        b.email === (cert.email ? decrypt(cert.email) : null) &&
        b.dob.split("T")[0] === cert.dob.toISOString().split("T")[0] &&
        b.course === decrypt(cert.course) &&
        b.rollNo === cert.rollNo &&
        b.adharHash === cert.adharHash;
    }

    res.json({
      verified: adharMatch && chainValid && dataMatch,
      studentName: decrypt(cert.studentName),
      course: decrypt(cert.course),
      rollNo: cert.rollNo,
      collegeName: cert.college?.name || null,
      link: cert.link ? decrypt(cert.link) : null,
      blockchainOk: chainValid,
      dataMatch,
      validAdhar: adharMatch,
    });
  } catch (err) {
    console.error("verify-certificate error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ---------------- Start server ----------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
