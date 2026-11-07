import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { eq } from 'drizzle-orm';
import { oauthClients } from './schema/tables';
import type { OAuthClient, OAuthClientStore, OAuthClientType, OAuthGrantType, RegisterClientInput } from './types';

/** `client_id`: prefix + 128 bits of entropy (hex) — recognizable and unguessable. */
export const generateClientId = (): string => `fw_client_${randomBytes(16).toString('hex')}`;

/** `client_secret`: prefix + 256 bits (hex); shown once, only its hash is stored. */
export const generateClientSecret = (): string => `fw_secret_${randomBytes(32).toString('hex')}`;

/** SHA-256 hex digest — the at-rest form of a client secret. */
export const hashClientSecret = (secret: string): string => createHash('sha256').update(secret).digest('hex');

/** Constant-time comparison of two SHA-256 hex digests (equal length by construction). */
function secretsMatch(candidateHash: string, storedHash: string): boolean {
  const candidate = Buffer.from(candidateHash, 'hex');
  const stored = Buffer.from(storedHash, 'hex');
  return candidate.length === stored.length && timingSafeEqual(candidate, stored);
}

/** Narrows the stored client type, failing loudly on an unexpected value. */
function clientType(value: string): OAuthClientType {
  if (value === 'confidential' || value === 'public') return value;
  throw new Error(`Unknown OAuth client type: ${value}`);
}

type ClientRow = typeof oauthClients.$inferSelect;

const toClient = (row: ClientRow): OAuthClient => ({
  id: row.id,
  name: row.name,
  type: clientType(row.type),
  redirectUris: row.redirectUris,
  allowedGrants: row.allowedGrants as readonly OAuthGrantType[],
  allowedScopes: row.allowedScopes,
  ...(row.secretHash ? { secretHash: row.secretHash } : {}),
});

/**
 * PostgreSQL-backed OAuth clients. Secrets are verified in constant time and
 * never returned after registration; public clients have no secret and must
 * authenticate with PKCE instead (`verifySecret` is always false for them).
 */
export class PgOAuthClientStore implements OAuthClientStore {
  constructor(private readonly connection: DatabaseConnection) {}

  async find(id: string): Promise<OAuthClient | null> {
    const rows = await this.connection.db.select().from(oauthClients).where(eq(oauthClients.id, id)).limit(1);
    const row = rows[0];
    return row ? toClient(row) : null;
  }

  async verifySecret(id: string, secret: string): Promise<boolean> {
    const rows = await this.connection.db
      .select({ secretHash: oauthClients.secretHash })
      .from(oauthClients)
      .where(eq(oauthClients.id, id))
      .limit(1);
    const stored = rows[0]?.secretHash;
    // Public clients carry no secret — never a match, PKCE is their only path.
    if (!stored) return false;
    return secretsMatch(hashClientSecret(secret), stored);
  }

  async register(input: RegisterClientInput): Promise<{ client: OAuthClient; secret?: string }> {
    const secret = input.type === 'confidential' ? generateClientSecret() : undefined;
    const rows = await this.connection.db
      .insert(oauthClients)
      .values({
        id: generateClientId(),
        name: input.name,
        type: input.type,
        redirectUris: [...input.redirectUris],
        allowedGrants: [...input.allowedGrants],
        allowedScopes: [...input.allowedScopes],
        secretHash: secret ? hashClientSecret(secret) : null,
      })
      .returning();
    const row = rows[0];
    if (!row) throw new Error('OAuth client insert returned no row');
    return { client: toClient(row), ...(secret ? { secret } : {}) };
  }

  async list(): Promise<readonly OAuthClient[]> {
    const rows = await this.connection.db.select().from(oauthClients).orderBy(oauthClients.createdAt);
    return rows.map(toClient);
  }
}
