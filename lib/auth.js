import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';

export function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

export function validateUsername(username) {
  return /^[a-z0-9_]{3,20}$/.test(username);
}

export function validatePassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 100;
}

export async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

export async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

export function isBcryptHash(hash) {
  return typeof hash === 'string' && /^\$2[ayb]\$.{56}$/.test(hash);
}

export function createSessionToken(user) {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET missing or too short.');
  }
  return jwt.sign(
    { userId: user.id, username: user.username, planType: user.plan_type },
    secret,
    { expiresIn: '7d' }
  );
}

export function getAuthenticatedUser(req) {
  try {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.sb_access_token;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

export function buildSessionCookie(token) {
  const domain = process.env.NODE_ENV === 'production' ? '.signaturesi.com' : undefined;
  return cookie.serialize('sb_access_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 604800,
    path: '/',
    domain
  });
}

export function buildLogoutCookie() {
  const domain = process.env.NODE_ENV === 'production' ? '.signaturesi.com' : undefined;
  return cookie.serialize('sb_access_token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: -1,
    path: '/',
    domain
  });
}
