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
