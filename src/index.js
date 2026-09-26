import "dotenv/config";
import express from "express";
import cors from "cors";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
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

/* =========================================================
   GOOGLE OAUTH
========================================================= */

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL ||
        "http://localhost:5000/api/auth/google/callback"
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value?.toLowerCase();

        if (!email) {
          return done(
            new Error("Google account email was not provided.")
          );
        }

        const users = readUsers();

        let user = users.find(
          (u) => u.email?.toLowerCase() === email
        );

        if (!user) {
          user = {
            id: crypto.randomUUID(),
            name:
              profile.displayName ||
              profile.name?.givenName ||
              "Google User",
            email,
            passwordHash: "",
            createdAt: new Date().toISOString(),
            provider: "google",
            googleId: profile.id
          };

          users.push(user);
        } else {
          user.googleId = profile.id;
          user.provider = user.provider || "google";
        }

        writeUsers(users);

        return done(null, user);
      } catch (error) {
        console.error("GOOGLE STRATEGY ERROR:", error);
        return done(error);
      }
    }
  )
);

const app = express();

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  cors({
    origin:
      process.env.CLIENT_URL ||
      "http://localhost:5173",
    credentials: true
  })
);

app.use(express.json());
app.use(passport.initialize());

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "ENVIRO METRICS SOLUTIONS API",
    time: new Date().toISOString()
  });
});

/* =========================================================
   REGISTER
========================================================= */

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

    if (
      users.some(
        (u) => u.email?.toLowerCase() === normalizedEmail
      )
    ) {
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

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const users = readUsers();

    const user = users.find(
      (u) =>
        u.email?.toLowerCase() ===
        email?.trim().toLowerCase()
    );

    if (
      !user ||
      !user.passwordHash ||
      !(await comparePassword(
        password || "",
        user.passwordHash
      ))
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

/* =========================================================
   CURRENT USER
========================================================= */

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

/* =========================================================
   FORGOT PASSWORD
========================================================= */

app.post("/api/auth/forgot-password", (req, res) => {
  const { email } = req.body;

  const users = readUsers();

  const user = users.find(
    (u) =>
      u.email?.toLowerCase() ===
      email?.trim().toLowerCase()
  );

  if (!user) {
    return res.json({
      message:
        "If the account exists, reset instructions have been created."
    });
  }

  const token = crypto.randomBytes(32).toString("hex");

  user.resetToken = token;
  user.resetExpires =
    Date.now() + 15 * 60 * 1000;

  writeUsers(users);

  res.json({
    message: "Reset instructions created.",
    devResetToken: token
  });
});

/* =========================================================
   RESET PASSWORD
========================================================= */

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

/* =========================================================
   GOOGLE LOGIN
========================================================= */

app.get(
  "/api/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false
  })
);

/* =========================================================
   GOOGLE CALLBACK
========================================================= */

app.get(
  "/api/auth/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect:
      `${
        process.env.CLIENT_URL ||
        "http://localhost:5173"
      }/?google=failed`
  }),
  (req, res) => {
    try {
      const token = createToken(req.user);

      const frontendUrl =
        process.env.CLIENT_URL ||
        "http://localhost:5173";

      res.redirect(
        `${frontendUrl}/?google=success&token=${encodeURIComponent(
          token
        )}`
      );
    } catch (error) {
      console.error(
        "GOOGLE CALLBACK ERROR:",
        error
      );

      const frontendUrl =
        process.env.CLIENT_URL ||
        "http://localhost:5173";

      res.redirect(
        `${frontendUrl}/?google=failed`
      );
    }
  }
);

/* =========================================================
   START SERVER
========================================================= */

const port = Number(process.env.PORT || 5000);

app.listen(port, () => {
  console.log(
    `ENVIRO METRICS SOLUTIONS API running on http://localhost:${port}`
  );
});