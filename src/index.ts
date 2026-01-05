// Types
export type {
  AuthConfig,
  Session,
  SessionWithToken,
  CookieOptions,
} from './types.js';

// Session functions
export {
  createSession,
  validateSession,
  getUser,
  deleteSession,
  deleteSessionById,
} from './session.js';

// Config utilities (for advanced use)
export { setConfig, clearConfig } from './config.js';

// Crypto utilities (if someone needs them)
export {
  generateSecureRandomString,
  hashSecret,
  constantTimeEqual,
} from './crypto.js';
