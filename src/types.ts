export interface Session {
  id: string;
  secretHash: Uint8Array;
  userId: string;
  createdAt: Date;
}

export interface SessionWithToken extends Session {
  token: string;
}

export interface CookieOptions {
  maxAge: number;
  httpOnly: boolean;
  secure: boolean;
  path: string;
  sameSite: 'lax' | 'strict' | 'none';
}

export interface JwtPayload {
  sessionId: string;
  userId: string;
  iat: number;
  exp: number;
}

export interface JwtConfig<TContext = unknown> {
  /**
   * Secret key for signing JWTs (min 32 characters recommended)
   */
  secret: string;

  /**
   * JWT lifespan in seconds (default: 300 = 5 minutes)
   * Keep short as per Lucia Auth recommendations
   */
  expiresIn?: number;

  /**
   * Get JWT from request (e.g., from Authorization header)
   * @param context - Optional context (e.g., request object, headers, etc.)
   */
  getJwtToken: (context?: TContext) => string | null | Promise<string | null>;

  /**
   * Set JWT in response (e.g., in Authorization header or response body)
   * @param token - The JWT token to set
   * @param context - Optional context (e.g., response object, headers, etc.)
   */
  setJwtToken: (token: string, context?: TContext) => void | Promise<void>;
}

export interface AuthConfig<TUser = any> {
  db: {
    insertSession: (session: Session) => Promise<void>;
    getSessionById: (sessionId: string) => Promise<Session | null>;
    deleteSession: (sessionId: string) => Promise<void>;
    getUserById: (userId: string) => Promise<TUser | null>;
  };

  cookie: {
    set: (name: string, value: string, options: CookieOptions) => void | Promise<void>;
    get: (name: string) => string | null | Promise<string | null>;
    delete: (name: string) => void | Promise<void>;
  };

  /**
   * Enable stateless JWT tokens for faster user lookups.
   * When enabled, getUser() will first check the JWT before hitting the database.
   * JWTs are short-lived (5 min default) and auto-refresh on valid session.
   */
  jwt?: JwtConfig;

  sessionExpiresIn?: number; // seconds, default 86400 (24 hours)
  cookieName?: string; // default "session_token"
}
