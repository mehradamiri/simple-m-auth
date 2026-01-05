const ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789'; // human readable, no confusing chars

export function generateSecureRandomString(): string {
  const bytes = new Uint8Array(24); // 120 bits of entropy
  crypto.getRandomValues(bytes);

  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += ALPHABET[bytes[i] >> 3];
  }
  return result;
}

export async function hashSecret(secret: string): Promise<Uint8Array> {
  const secretBytes = new TextEncoder().encode(secret);
  const hashBuffer = await crypto.subtle.digest('SHA-256', secretBytes);
  return new Uint8Array(hashBuffer);
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let c = 0;
  for (let i = 0; i < a.byteLength; i++) {
    c |= a[i] ^ b[i];
  }
  return c === 0;
}

export function parseToken(token: string): { id: string; secret: string } | null {
  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }
  return { id: parts[0], secret: parts[1] };
}

// JWT utilities using HMAC SHA-256

function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function getHmacKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export interface JwtPayload {
  sessionId: string;
  userId: string;
  iat: number;
  exp: number;
}

const JWT_HEADER = { alg: 'HS256', typ: 'JWT' };

export async function signJwt(payload: JwtPayload, secret: string): Promise<string> {
  const encoder = new TextEncoder();

  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(JWT_HEADER)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));

  return `${data}.${base64UrlEncode(new Uint8Array(signature))}`;
}

export async function verifyJwt(token: string, secret: string): Promise<JwtPayload | null> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  try {
    // Verify header
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
    if (header.alg !== 'HS256' || header.typ !== 'JWT') {
      return null;
    }

    // Verify signature
    const key = await getHmacKey(secret);
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const encoder = new TextEncoder();

    const signatureArray = new Uint8Array(signature);
    const isValid = await crypto.subtle.verify('HMAC', key, signatureArray, encoder.encode(data));
    if (!isValid) {
      return null;
    }

    // Parse and validate payload
    const payload: JwtPayload = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(payloadB64))
    );

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}
