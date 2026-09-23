import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

export function createToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, name: user.name },
    process.env.JWT_SECRET || "dev-only-secret-change-me",
    { expiresIn: "7d" }
  );
}

export function verifyToken(token) {
  return jwt.verify(
    token,
    process.env.JWT_SECRET || "dev-only-secret-change-me"
  );
}
