import type { AuthConfig } from './types.js';
import { pathToFileURL } from 'url';
import { existsSync } from 'fs';
import { join } from 'path';

let cachedConfig: AuthConfig | null = null;

const CONFIG_FILENAMES = [
  'auth.config.ts',
  'auth.config.js',
  'auth.config.mjs',
];

export async function loadConfig(): Promise<AuthConfig> {
  if (cachedConfig) {
    return cachedConfig;
  }

  const cwd = process.cwd();

  for (const filename of CONFIG_FILENAMES) {
    const configPath = join(cwd, filename);
    
    if (existsSync(configPath)) {
      try {
        const configModule = await import(pathToFileURL(configPath).href);
        const config = configModule.authConfig || configModule.default;
        
        if (!config) {
          throw new Error(`Config file ${filename} must export 'authConfig' or default export`);
        }

        validateConfig(config);
        cachedConfig = config;
        return config;
      } catch (error) {
        throw new Error(`Failed to load ${filename}: ${error}`);
      }
    }
  }

  throw new Error(
    `No auth config found. Create one of: ${CONFIG_FILENAMES.join(', ')} in your project root.`
  );
}

function validateConfig(config: any): asserts config is AuthConfig {
  if (!config.db) {
    throw new Error('AuthConfig.db is required');
  }
  if (typeof config.db.insertSession !== 'function') {
    throw new Error('AuthConfig.db.insertSession must be a function');
  }
  if (typeof config.db.getSessionById !== 'function') {
    throw new Error('AuthConfig.db.getSessionById must be a function');
  }
  if (typeof config.db.deleteSession !== 'function') {
    throw new Error('AuthConfig.db.deleteSession must be a function');
  }
  if (typeof config.db.getUserById !== 'function') {
    throw new Error('AuthConfig.db.getUserById must be a function');
  }
  if (!config.cookie) {
    throw new Error('AuthConfig.cookie is required');
  }
  if (typeof config.cookie.set !== 'function') {
    throw new Error('AuthConfig.cookie.set must be a function');
  }
  if (typeof config.cookie.get !== 'function') {
    throw new Error('AuthConfig.cookie.get must be a function');
  }
  if (typeof config.cookie.delete !== 'function') {
    throw new Error('AuthConfig.cookie.delete must be a function');
  }
}

// Allow manual config setting (useful for testing or non-standard setups)
export function setConfig(config: AuthConfig): void {
  validateConfig(config);
  cachedConfig = config;
}

export function clearConfig(): void {
  cachedConfig = null;
}
