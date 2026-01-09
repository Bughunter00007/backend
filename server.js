const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const xss = require("xss-clean");
const mongoSanitize = require("express-mongo-sanitize");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3001;

// Trust proxy (IMPORTANT for Heroku / Render / Vercel)
app.set("trust proxy", 1);

/* -------------------- HELPERS -------------------- */
function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    return xff.split(",")[0].trim();
  }
  return req.ip;
}

/* -------------------- SECURITY -------------------- */
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"]
      }
    },
    frameguard: { action: "deny" },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
  })
);

/* -------------------- CORS -------------------- */
const allowedOrigins = [
  "https://jalwan.app",
  "https://www.jalwan.app",
  "http://localhost:3000",
  "http://localhost:3001"
];

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.log("❌ CORS blocked:", origin);
    callback(new Error("CORS policy violation"));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10kb" }));
app.use(xss());
app.use(mongoSanitize());

/* -------------------- RATE LIMITING -------------------- */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === "/health"
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: "Too many contact requests, try again in 1 hour",
  keyGenerator: (req) => getClientIp(req)
});

app.use(globalLimiter);

/* -------------------- VALIDATION -------------------- */
function isValidEmail(email) {
  return (
    typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
    email.length <= 254
  );
}

function isValidUrl(url) {
  try {
    const u = new URL(url);
    if (!["http:", "https:"].includes(u.protocol)) return false;

    const privateHosts = [
      /^localhost$/i,
      /^127\./,
      /^10\./,
      /^192\.168\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^::1$/
    ];

    return !privateHosts.some((r) => r.test(u.hostname));
  } catch {
    return false;
  }
}

function validateContactRequest(req, res, next) {
  const { name, email, url, message, description } = req.body || {};
  const finalMessage = message || description || "";

  if (!name || name.trim().length < 2 || name.length > 100) {
    return res.status(400).json({ error: "Invalid name" });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Invalid email" });
  }

  if (!isValidUrl(url)) {
    return res.status(400).json({ error: "Invalid URL" });
  }

  if (finalMessage && finalMessage.length > 500) {
    return res.status(400).json({ error: "Message too long" });
  }

  next();
}

/* -------------------- ROUTES -------------------- */
app.get("/health", (_req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.post(
  "/contact",
  contactLimiter,
  validateContactRequest,
  async (req, res) => {
    const { name, email, url, message, description } = req.body;
    const finalMessage = message || description || "";

    const clientIp = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "Unknown";

    const sanitizedName = name.trim().substring(0, 100);
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedMessage = finalMessage
      ? finalMessage.trim().substring(0, 500)
      : "";

    const emailBody = [
      `Name: ${sanitizedName}`,
      `Email: ${sanitizedEmail}`,
      `Web App URL: ${url}`,
      sanitizedMessage ? `Message: ${sanitizedMessage}` : null,
      "",
      "---- META ----",
      `IP Address: ${clientIp}`,
      `User-Agent: ${userAgent}`,
      `Submitted At: ${new Date().toISOString()}`
    ]
      .filter(Boolean)
      .join("\n");

    if (
      !process.env.SMTP_HOST ||
      !process.env.SMTP_USER ||
      !process.env.SMTP_PASS ||
      !process.env.TO_EMAIL
    ) {
      console.error("❌ SMTP env missing");
      return res.status(500).json({ error: "Email not configured" });
    }

    try {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: process.env.SMTP_SECURE === "true",
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        },
        connectionTimeout: 5000,
        socketTimeout: 5000
      });

      await transporter.verify();

      await transporter.sendMail({
        from: process.env.FROM_EMAIL || process.env.SMTP_USER,
        to: process.env.TO_EMAIL,
        replyTo: sanitizedEmail,
        subject: `[Jalwan] New Contact from ${sanitizedName}`,
        text: emailBody,
        headers: {
          "X-Client-IP": clientIp,
          "X-Mailer": "Jalwan Contact API"
        }
      });

      return res.json({ success: true });
    } catch (err) {
      console.error("❌ Mail error:", err.message);
      return res
        .status(503)
        .json({ error: "Unable to send message" });
    }
  }
);

/* -------------------- ERRORS -------------------- */
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  if (err.message === "CORS policy violation") {
    return res.status(403).json({ error: "CORS blocked" });
  }
  res.status(500).json({ error: "Internal server error" });
});

/* -------------------- START -------------------- */
app.listen(PORT, () => {
  console.log(`🚀 Contact API running on port ${PORT}`);
  console.log(`ENV: ${process.env.NODE_ENV || "development"}`);
});
