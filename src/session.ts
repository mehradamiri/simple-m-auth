import type { Session, SessionWithToken } from './types.js';
import { loadConfig } from './config.js';
import {
  generateSecureRandomString,
  hashSecret,
  constantTimeEqual,
  parseToken,
} from './crypto.js';

const DEFAULT_EXPIRES_IN = 60 * 60 * 24; // 24 hours
const DEFAULT_COOKIE_NAME = 'session_token';

/**
 * Create a new session for a user and set the cookie
 */
export async function createSession(userId: string): Promise<SessionWithToken> {
  const config = await loadConfig();

  const id = generateSecureRandomString();
  const secret = generateSecureRandomString();
  const secretHash = await hashSecret(secret);
  const createdAt = new Date();
  const token = `${id}.${secret}`;

  const session: SessionWithToken = {
    id,
    secretHash,
    userId,
    createdAt,
    token,
  };

  await config.db.insertSession({
    id,
    secretHash,
    userId,
    createdAt,
  });

  const cookieName = config.cookieName ?? DEFAULT_COOKIE_NAME;
  const maxAge = config.sessionExpiresIn ?? DEFAULT_EXPIRES_IN;

  await config.cookie.set(cookieName, token, {
    maxAge,
    httpOnly: true,
    secure: true,
    path: '/',
    sameSite: 'lax',
  });

  return session;
}

/**
 * Validate the current session from cookie
 * Returns the session if valid, null otherwise
 */
export async function validateSession(): Promise<Session | null> {
  const config = await loadConfig();
  const cookieName = config.cookieName ?? DEFAULT_COOKIE_NAME;
  const expiresIn = config.sessionExpiresIn ?? DEFAULT_EXPIRES_IN;

  const token = await config.cookie.get(cookieName);
  if (!token) {
    return null;
  }

  const parsed = parseToken(token);
  if (!parsed) {
    return null;
  }

  const session = await config.db.getSessionById(parsed.id);
  if (!session) {
    return null;
  }

  // Check expiration
  const now = Date.now();
  const sessionAge = now - session.createdAt.getTime();
  if (sessionAge >= expiresIn * 1000) {
    await config.db.deleteSession(session.id);
    await config.cookie.delete(cookieName);
    return null;
  }

  // Verify secret
  const tokenSecretHash = await hashSecret(parsed.secret);
  if (!constantTimeEqual(tokenSecretHash, session.secretHash)) {
    return null;
  }

  return session;
}

/**
 * Get the current user from session
 * Returns null if no valid session or user not found
 */
export async function getUser<TUser = any>(): Promise<TUser | null> {
  const config = await loadConfig();
  const session = await validateSession();

  if (!session) {
    return null;
  }

  return config.db.getUserById(session.userId);
}

/**
 * Delete the current session and clear cookie
 */
export async function deleteSession(): Promise<void> {
  const config = await loadConfig();
  const cookieName = config.cookieName ?? DEFAULT_COOKIE_NAME;

  const token = await config.cookie.get(cookieName);
  if (!token) {
    return;
  }

  const parsed = parseToken(token);
  if (parsed) {
    await config.db.deleteSession(parsed.id);
  }

  await config.cookie.delete(cookieName);
}

/**
 * Delete a specific session by ID (useful for "logout all devices")
 */
export async function deleteSessionById(sessionId: string): Promise<void> {
  const config = await loadConfig();
  await config.db.deleteSession(sessionId);
}
