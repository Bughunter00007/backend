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

// Trust proxy for Heroku and other proxies
app.set("trust proxy", 1);

// Security headers with helmet
app.use(helmet({
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
}));

// CORS setup: allow only your frontends
const allowedOrigins = [
  "https://jalwan.app",
  "https://www.jalwan.app",
  "http://localhost:3000",
  "http://localhost:3001"
];
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.log("CORS blocked:", origin);
    return callback(new Error("CORS policy violation"));
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10kb" })); // Reduced from 100kb
app.use(xss()); // XSS attack prevention
app.use(mongoSanitize()); // NoSQL injection prevention

// Stricter rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, please try again later",
  skip: (req) => {
    // Skip health check from rate limiting
    return req.path === "/health";
  }
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Max 3 contact requests per hour per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many contact requests, please try again in an hour",
  keyGenerator: (req) => {
    // Use IP address or forwarded IP for rate limiting
    return req.headers["x-forwarded-for"] || req.ip;
  }
});

app.use(limiter);

// Request validation middleware
function validateContactRequest(req, res, next) {
  const { name, email, url, message, description } = req.body || {};
  const finalMessage = message || description || "";

  // Validate name
  if (!name || typeof name !== "string" || name.trim().length < 2) {
    return res.status(400).json({ error: "Name must be at least 2 characters" });
  }
  if (name.length > 100) {
    return res.status(400).json({ error: "Name must be less than 100 characters" });
  }

  // Validate email
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Valid email is required" });
  }

  // Validate URL
  if (!isValidUrl(url)) {
    return res.status(400).json({ error: "Valid web application URL is required" });
  }

  // Validate optional message
  if (finalMessage && typeof finalMessage === "string") {
    if (finalMessage.length > 500) {
      return res.status(400).json({ error: "Message must be less than 500 characters" });
    }
  }

  next();
}

// Validation helpers
function isValidEmail(email) {
  // RFC 5322 simplified but strict regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return typeof email === "string" && emailRegex.test(email) && email.length <= 254;
}

function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    // Only allow http and https
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return false;
    }
    // Prevent localhost and private IP addresses
    const hostname = parsed.hostname;
    const privatePatterns = [
      /^localhost$/i,
      /^127\.0\.0\.1$/,
      /^::1$/,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./
    ];
    
    if (privatePatterns.some(pattern => pattern.test(hostname))) {
      return false;
    }
    
    return true;
  } catch (e) {
    return false;
  }
}

// Health check endpoint
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Contact endpoint with validation and rate limiting
app.post("/contact", contactLimiter, validateContactRequest, async (req, res) => {
  const { name, email, url, message, description } = req.body;
  const finalMessage = message || description || "";

  // Sanitize inputs
  const sanitizedName = name.trim().substring(0, 100);
  const sanitizedEmail = email.toLowerCase().trim();
  const sanitizedMessage = finalMessage ? finalMessage.trim().substring(0, 500) : "";

  const body = [
    `Name: ${sanitizedName}`,
    `Email: ${sanitizedEmail}`,
    `Web App URL: ${url}`,
    sanitizedMessage ? `Message: ${sanitizedMessage}` : null
  ].filter(Boolean).join("\n");

  // Verify required environment variables
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS || !process.env.TO_EMAIL) {
    console.error("Missing SMTP configuration");
    return res.status(500).json({ error: "Email service not configured" });
  }

  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === "true", // Use TLS encryption
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      // Connection timeout
      connectionTimeout: 5000,
      socketTimeout: 5000
    });

    // Verify connection before sending
    await transporter.verify();

    const info = await transporter.sendMail({
      from: process.env.FROM_EMAIL || process.env.SMTP_USER,
      to: process.env.TO_EMAIL,
      replyTo: sanitizedEmail,
      subject: `[Jalwan] New Pentest Request from ${sanitizedName}`,
      text: body,
      headers: {
        "X-Mailer": "Jalwan Contact API"
      }
    });

    console.log("Email sent:", info.messageId);
    return res.status(200).json({ success: true, message: "Request received successfully" });
  } catch (err) {
    console.error("Email service error:", err.message);
    // Don't expose internal error details to client
    return res.status(503).json({ error: "Unable to process request, please try again later" });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  
  // Handle CORS errors
  if (err.message === "CORS policy violation") {
    return res.status(403).json({ error: "CORS policy violation" });
  }

  // Generic error response
  res.status(err.status || 500).json({ 
    error: process.env.NODE_ENV === "production" 
      ? "Internal server error" 
      : err.message 
  });
});

app.listen(PORT, () => {
  console.log(`Contact API running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});
