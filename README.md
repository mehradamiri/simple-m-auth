# simple-m-auth

Dead simple session-based authentication. Just create `auth.config.ts` and go.

Based on [Lucia Auth](https://lucia-auth.com) principles: separate session ID and secret, SHA-256 hashed secrets, constant-time comparison.

## Install

```bash
npm install simple-m-auth
```

## Setup

Create `auth.config.ts` in your project root:

```typescript
import type { AuthConfig } from 'simple-m-auth';
import { prisma } from './db';

export const authConfig: AuthConfig = {
  db: {
    insertSession: async (session) => {
      await prisma.session.create({
        data: {
          id: session.id,
          secretHash: Buffer.from(session.secretHash),
          userId: session.userId,
          createdAt: session.createdAt,
        },
      });
    },

    getSessionById: async (sessionId) => {
      const session = await prisma.session.findUnique({
        where: { id: sessionId },
      });
      if (!session) return null;
      return {
        ...session,
        secretHash: new Uint8Array(session.secretHash),
      };
    },

    deleteSession: async (sessionId) => {
      await prisma.session.deleteMany({ where: { id: sessionId } });
    },

    getUserById: async (userId) => {
      return prisma.user.findUnique({ where: { id: userId } });
    },
  },

  cookie: {
    // Example for Next.js App Router (context not needed)
    set: async (name, value, options, ctx?) => {
      const { cookies } = await import('next/headers');
      const cookieStore = await cookies();
      cookieStore.set(name, value, options);
    },

    get: async (name, ctx?) => {
      const { cookies } = await import('next/headers');
      const cookieStore = await cookies();
      return cookieStore.get(name)?.value ?? null;
    },

    delete: async (name, ctx?) => {
      const { cookies } = await import('next/headers');
      const cookieStore = await cookies();
      cookieStore.delete(name);
    },
  },

  sessionExpiresIn: 60 * 60 * 24 * 7, // 1 week
  cookieName: 'session_token',
};
```

## Database Schema

```sql
CREATE TABLE session (
  id TEXT PRIMARY KEY,
  secret_hash BLOB NOT NULL,
  user_id TEXT NOT NULL REFERENCES user(id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

Prisma:

```prisma
model Session {
  id         String   @id
  secretHash Bytes    @map("secret_hash")
  userId     String   @map("user_id")
  user       User     @relation(fields: [userId], references: [id])
  createdAt  DateTime @default(now()) @map("created_at")

  @@map("session")
}
```

## Usage

```typescript
import { createSession, validateSession, getUser, deleteSession } from 'simple-m-auth';

// All functions accept an optional context parameter for frameworks that need it
// e.g., createSession(userId, ctx), getUser(ctx), validateSession(ctx), deleteSession(ctx)

// Login - create session after verifying password
async function login(userId: string) {
  const session = await createSession(userId);
  // Cookie is automatically set
  return session;
}

// Check if user is authenticated
async function auth() {
  const session = await validateSession();
  if (!session) {
    redirect('/login');
  }
  return session;
}

// Get current user
async function getCurrentUser() {
  const user = await getUser();
  return user; // null if not authenticated
}

// Logout
async function logout() {
  await deleteSession();
  // Cookie is automatically cleared
}
```

## JWT Support (Stateless Tokens)

Enable short-lived JWTs for faster authentication. Based on [Lucia Auth stateless tokens](https://lucia-auth.com/sessions/stateless-tokens) principles:

- JWTs are short-lived (5 minutes default)
- `getUser()` checks JWT first (no DB lookup if valid)
- Falls back to session validation if JWT expired
- Auto-refreshes JWT when session is valid

Add `jwt` config:

```typescript
export const authConfig: AuthConfig = {
  db: { /* ... */ },
  cookie: { /* ... */ },

  jwt: {
    secret: 'your-32-character-or-longer-secret-key',
    expiresIn: 300, // 5 minutes (default)

    getJwtToken: (ctx?) => {
      // Get from Authorization header
      return ctx?.req?.headers.get('Authorization')?.replace('Bearer ', '') ?? null;
    },

    setJwtToken: (token, ctx?) => {
      // Set in response header
      ctx?.res?.headers.set('Authorization', `Bearer ${token}`);
    },
  },
};
```

Pass context to functions:

```typescript
// With context (for frameworks like Express, Hono, etc.)
const ctx = { req, res };
const session = await createSession(userId, ctx);
const user = await getUser(ctx);
const valid = await validateSession(ctx);
await deleteSession(ctx);

// Without context (Next.js App Router, or when using closures)
const user = await getUser();
```

## Next.js Example

```typescript
// app/api/auth/login/route.ts
import { createSession } from 'simple-m-auth';
import { verifyPassword } from '@/lib/password';
import { prisma } from '@/lib/db';

export async function POST(request: Request) {
  const { email, password } = await request.json();

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !await verifyPassword(password, user.passwordHash)) {
    return Response.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  await createSession(user.id);
  return Response.json({ success: true });
}
```

```typescript
// app/api/auth/logout/route.ts
import { deleteSession } from 'simple-m-auth';

export async function POST() {
  await deleteSession();
  return Response.json({ success: true });
}
```

```typescript
// lib/auth.ts
import { getUser } from 'simple-m-auth';
import { redirect } from 'next/navigation';

export async function requireAuth() {
  const user = await getUser();
  if (!user) {
    redirect('/login');
  }
  return user;
}
```

## License

MIT
