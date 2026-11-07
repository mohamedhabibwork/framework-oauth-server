import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { and, eq, gt, isNull, lt, sql } from 'drizzle-orm';
import { oauthAccessTokens, oauthRefreshTokens } from './schema/tables';
import type {
  IssueAccessInput,
  IssuedAccessToken,
  IssueRefreshInput,
  OAuthAccessRecord,
  OAuthRefreshRecord,
  OAuthTokenStore,
} from './types';

/** Opaque token value: prefix + 256 bits of entropy (hex); only its hash is stored. */
export const generateOAuthToken = (prefix: string): string => `${prefix}${randomBytes(32).toString('hex')}`;

/** SHA-256 hex digest — the at-rest form of an access/refresh token. */
export const hashOAuthToken = (value: string): string => createHash('sha256').update(value).digest('hex');

type AccessRow = typeof oauthAccessTokens.$inferSelect;
type RefreshRow = typeof oauthRefreshTokens.$inferSelect;

const toAccessRecord = (row: AccessRow): OAuthAccessRecord => ({
  tokenHash: row.tokenHash,
  clientId: row.clientId,
  userId: row.userId,
  scopes: row.scopes,
  expiresAt: row.expiresAt,
  revokedAt: row.revokedAt,
});

const toRefreshRecord = (row: RefreshRow): OAuthRefreshRecord => ({
  tokenHash: row.tokenHash,
  clientId: row.clientId,
  userId: row.userId,
  scopes: row.scopes,
  expiresAt: row.expiresAt,
  revokedAt: row.revokedAt,
});

/**
 * PostgreSQL-backed opaque access and refresh tokens. Lookups resolve only
 * unrevoked, unexpired rows (checked in SQL). Revocation flips `revoked_at`
 * across both tables, and `prune` deletes expired rows so the tables stay
 * bounded. JWT access tokens (see `JwtTokenIssuer`) are stateless and are not
 * tracked here; only refresh tokens are.
 */
export class PgOAuthTokenStore implements OAuthTokenStore {
  constructor(private readonly connection: DatabaseConnection) {}

  async issueAccess(input: IssueAccessInput): Promise<IssuedAccessToken> {
    const token = generateOAuthToken('fw_at_');
    const rows = await this.connection.db
      .insert(oauthAccessTokens)
      .values({
        tokenHash: hashOAuthToken(token),
        clientId: input.clientId,
        userId: input.userId,
        scopes: [...input.scopes],
        expiresAt: input.expiresAt,
      })
      .returning({ expiresAt: oauthAccessTokens.expiresAt });
    const row = rows[0];
    if (!row) throw new Error('OAuth access token insert returned no row');
    return { token, expiresAt: row.expiresAt, scopes: input.scopes };
  }

  async issueRefresh(input: IssueRefreshInput): Promise<string> {
    const token = generateOAuthToken('fw_rt_');
    await this.connection.db.insert(oauthRefreshTokens).values({
      tokenHash: hashOAuthToken(token),
      clientId: input.clientId,
      userId: input.userId,
      scopes: [...input.scopes],
      expiresAt: input.expiresAt,
    });
    return token;
  }

  async findAccess(token: string): Promise<OAuthAccessRecord | null> {
    const rows = await this.connection.db
      .select()
      .from(oauthAccessTokens)
      .where(
        and(
          eq(oauthAccessTokens.tokenHash, hashOAuthToken(token)),
          isNull(oauthAccessTokens.revokedAt),
          gt(oauthAccessTokens.expiresAt, sql`now()`),
        ),
      )
      .limit(1);
    const row = rows[0];
    return row ? toAccessRecord(row) : null;
  }

  async findRefresh(token: string): Promise<OAuthRefreshRecord | null> {
    const rows = await this.connection.db
      .select()
      .from(oauthRefreshTokens)
      .where(
        and(
          eq(oauthRefreshTokens.tokenHash, hashOAuthToken(token)),
          isNull(oauthRefreshTokens.revokedAt),
          gt(oauthRefreshTokens.expiresAt, sql`now()`),
        ),
      )
      .limit(1);
    const row = rows[0];
    return row ? toRefreshRecord(row) : null;
  }

  async revoke(token: string): Promise<boolean> {
    const hash = hashOAuthToken(token);
    const access = await this.connection.db
      .update(oauthAccessTokens)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(oauthAccessTokens.tokenHash, hash), isNull(oauthAccessTokens.revokedAt)))
      .returning({ id: oauthAccessTokens.id });
    if (access.length > 0) return true;
    const refresh = await this.connection.db
      .update(oauthRefreshTokens)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(oauthRefreshTokens.tokenHash, hash), isNull(oauthRefreshTokens.revokedAt)))
      .returning({ id: oauthRefreshTokens.id });
    return refresh.length > 0;
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const access = await this.connection.db
      .update(oauthAccessTokens)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(oauthAccessTokens.userId, userId), isNull(oauthAccessTokens.revokedAt)))
      .returning({ id: oauthAccessTokens.id });
    const refresh = await this.connection.db
      .update(oauthRefreshTokens)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(oauthRefreshTokens.userId, userId), isNull(oauthRefreshTokens.revokedAt)))
      .returning({ id: oauthRefreshTokens.id });
    return access.length + refresh.length;
  }

  async prune(now: Date = new Date()): Promise<number> {
    const access = await this.connection.db
      .delete(oauthAccessTokens)
      .where(lt(oauthAccessTokens.expiresAt, now))
      .returning({ id: oauthAccessTokens.id });
    const refresh = await this.connection.db
      .delete(oauthRefreshTokens)
      .where(lt(oauthRefreshTokens.expiresAt, now))
      .returning({ id: oauthRefreshTokens.id });
    return access.length + refresh.length;
  }
}
