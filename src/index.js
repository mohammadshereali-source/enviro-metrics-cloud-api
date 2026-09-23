import "dotenv/config";
import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  hashPassword,
  comparePassword,
  createToken,
  verifyToken
} from "./auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dataDir = path.join(__dirname, "..", "data");
const usersFile = path.join(dataDir, "users.json");

fs.mkdirSync(dataDir, { recursive: true });

if (!fs.existsSync(usersFile)) {
  fs.writeFileSync(usersFile, "[]");
}

function readUsers() {
  return JSON.parse(fs.readFileSync(usersFile, "utf8"));
}

function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  };
}

// Create Express application
const app = express();

// Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true
  })
);

app.use(express.json());

// Health check
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "ENVIRO METRICS SOLUTIONS API",
    time: new Date().toISOString()
  });
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({
        message: "Name, email and password are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters."
      });
    }

    const users = readUsers();
    const normalizedEmail = email.trim().toLowerCase();

    if (users.some((u) => u.email === normalizedEmail)) {
      return res.status(409).json({
        message: "An account with this email already exists."
      });
    }

    const user = {
      id: crypto.randomUUID(),
      name: name.trim(),
      email: normalizedEmail,
      passwordHash: await hashPassword(password),
      createdAt: new Date().toISOString()
    };

    users.push(user);
    writeUsers(users);

    const token = createToken(user);

    res.status(201).json({
      user: publicUser(user),
      token
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      message: "Registration failed."
    });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const users = readUsers();

    const user = users.find(
      (u) => u.email === email?.trim().toLowerCase()
    );

    if (
      !user ||
      !(await comparePassword(password || "", user.passwordHash))
    ) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const token = createToken(user);

    res.json({
      user: publicUser(user),
      token
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      message: "Login failed."
    });
  }
});

// Current logged-in user
app.get("/api/auth/me", (req, res) => {
  try {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Missing token."
      });
    }

    const token = auth.slice(7);
    const payload = verifyToken(token);

    const user = readUsers().find(
      (u) => u.id === payload.sub
    );

    if (!user) {
      return res.status(401).json({
        message: "User not found."
      });
    }

    res.json({
      user: publicUser(user)
    });
  } catch (error) {
    console.error("AUTH ME ERROR:", error.message);

    res.status(401).json({
      message: "Invalid or expired token."
    });
  }
});

// Forgot password
app.post("/api/auth/forgot-password", (req, res) => {
  const { email } = req.body;

  const users = readUsers();

  const user = users.find(
    (u) => u.email === email?.trim().toLowerCase()
  );

  if (!user) {
    return res.json({
      message:
        "If the account exists, reset instructions have been created."
    });
  }

  const token = crypto.randomBytes(32).toString("hex");

  user.resetToken = token;
  user.resetExpires = Date.now() + 15 * 60 * 1000;

  writeUsers(users);

  res.json({
    message: "Reset instructions created.",
    devResetToken: token
  });
});

// Reset password
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password || password.length < 8) {
      return res.status(400).json({
        message:
          "Valid token and password (8+ characters) are required."
      });
    }

    const users = readUsers();

    const user = users.find(
      (u) =>
        u.resetToken === token &&
        u.resetExpires > Date.now()
    );

    if (!user) {
      return res.status(400).json({
        message: "Reset token is invalid or expired."
      });
    }

    user.passwordHash = await hashPassword(password);

    delete user.resetToken;
    delete user.resetExpires;

    writeUsers(users);

    res.json({
      message: "Password reset successfully."
    });
  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error);

    res.status(500).json({
      message: "Password reset failed."
    });
  }
});

// Google OAuth placeholder
app.get("/api/auth/google", (_req, res) => {
  res.status(501).json({
    message:
      "Google OAuth is not configured yet. Add Google OAuth credentials and callback handling before production use."
  });
});

// Start server
const port = Number(process.env.PORT || 5000);

app.listen(port, () => {
  console.log(
    `ENVIRO METRICS SOLUTIONS API running on http://localhost:${port}`
  );
});