import type { Session, SessionWithToken, JwtPayload } from './types.js';
import { loadConfig } from './config.js';
import {
  generateSecureRandomString,
  hashSecret,
  constantTimeEqual,
  parseToken,
  signJwt,
  verifyJwt,
} from './crypto.js';

const DEFAULT_EXPIRES_IN = 60 * 60 * 24; // 24 hours
const DEFAULT_COOKIE_NAME = 'session_token';
const DEFAULT_JWT_EXPIRES_IN = 60 * 5; // 5 minutes (short-lived per Lucia Auth)

/**
 * Create a JWT for a session
 */
async function createJwtForSession(
  sessionId: string,
  userId: string,
  secret: string,
  expiresIn: number
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: JwtPayload = {
    sessionId,
    userId,
    iat: now,
    exp: now + expiresIn,
  };
  return signJwt(payload, secret);
}

/**
 * Create a new session for a user and set the cookie
 * @param userId - The user ID to create a session for
 * @param context - Optional context to pass to JWT handlers (e.g., request/response objects)
 */
export async function createSession<TContext = unknown>(
  userId: string,
  context?: TContext
): Promise<SessionWithToken> {
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
  }, context);

  // Issue JWT if enabled
  if (config.jwt) {
    const jwtExpiresIn = config.jwt.expiresIn ?? DEFAULT_JWT_EXPIRES_IN;
    const jwt = await createJwtForSession(id, userId, config.jwt.secret, jwtExpiresIn);
    await config.jwt.setJwtToken(jwt, context);
  }

  return session;
}

/**
 * Validate the current session from cookie
 * Returns the session if valid, null otherwise
 * @param context - Optional context to pass to cookie handlers
 */
export async function validateSession<TContext = unknown>(
  context?: TContext
): Promise<Session | null> {
  const config = await loadConfig();
  const cookieName = config.cookieName ?? DEFAULT_COOKIE_NAME;
  const expiresIn = config.sessionExpiresIn ?? DEFAULT_EXPIRES_IN;

  const token = await config.cookie.get(cookieName, context);
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
    await config.cookie.delete(cookieName, context);
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
 * When JWT is enabled, first checks JWT for fast validation.
 * If JWT is expired/invalid, falls back to session validation and refreshes JWT.
 * Returns null if no valid session or user not found.
 * @param context - Optional context to pass to JWT handlers (e.g., request/response objects)
 */
export async function getUser<TUser = any, TContext = unknown>(
  context?: TContext
): Promise<TUser | null> {
  const config = await loadConfig();

  // If JWT is enabled, try JWT first (fast path - no DB lookup)
  if (config.jwt) {
    const jwtToken = await config.jwt.getJwtToken(context);

    if (jwtToken) {
      const payload = await verifyJwt(jwtToken, config.jwt.secret);

      if (payload) {
        // JWT is valid, get user directly without session validation
        return config.db.getUserById(payload.userId);
      }
    }

    // JWT missing or invalid - fall back to session validation
    const session = await validateSession(context);
    if (!session) {
      return null;
    }

    // Session is valid - refresh the JWT
    const jwtExpiresIn = config.jwt.expiresIn ?? DEFAULT_JWT_EXPIRES_IN;
    const newJwt = await createJwtForSession(
      session.id,
      session.userId,
      config.jwt.secret,
      jwtExpiresIn
    );
    await config.jwt.setJwtToken(newJwt, context);

    return config.db.getUserById(session.userId);
  }

  // No JWT configured - use regular session validation
  const session = await validateSession(context);

  if (!session) {
    return null;
  }

  return config.db.getUserById(session.userId);
}

/**
 * Delete the current session and clear cookie
 * @param context - Optional context to pass to cookie handlers
 */
export async function deleteSession<TContext = unknown>(
  context?: TContext
): Promise<void> {
  const config = await loadConfig();
  const cookieName = config.cookieName ?? DEFAULT_COOKIE_NAME;

  const token = await config.cookie.get(cookieName, context);
  if (!token) {
    return;
  }

  const parsed = parseToken(token);
  if (parsed) {
    await config.db.deleteSession(parsed.id);
  }

  await config.cookie.delete(cookieName, context);
}

/**
 * Delete a specific session by ID (useful for "logout all devices")
 */
export async function deleteSessionById(sessionId: string): Promise<void> {
  const config = await loadConfig();
  await config.db.deleteSession(sessionId);
}
