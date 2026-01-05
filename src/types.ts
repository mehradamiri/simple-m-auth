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

  sessionExpiresIn?: number; // seconds, default 86400 (24 hours)
  cookieName?: string; // default "session_token"
}
