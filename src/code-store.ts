import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import { oauthAuthCodes } from './schema/tables';
import type { IssueCodeInput, OAuthCodeRecord, OAuthCodeStore } from './types';

/** Single-use authorization code: prefix + 256 bits (hex); only its hash is stored. */
export const generateAuthCode = (): string => `fw_code_${randomBytes(32).toString('hex')}`;

/** SHA-256 hex digest — the at-rest form of an authorization code. */
export const hashAuthCode = (code: string): string => createHash('sha256').update(code).digest('hex');

/**
 * PostgreSQL-backed authorization codes. `consume` is a single atomic
 * `UPDATE ... RETURNING`: the first caller to match the un-consumed, unexpired
 * row for the right client wins, and any replay finds `consumed_at` already set
 * and gets `null`. PKCE verification is the caller's job — the challenge is
 * returned verbatim so the token endpoint can check the verifier.
 */
export class PgOAuthCodeStore implements OAuthCodeStore {
  constructor(
    private readonly connection: DatabaseConnection,
    private readonly ttlSeconds: number,
  ) {}

  async issue(input: IssueCodeInput): Promise<string> {
    const code = generateAuthCode();
    await this.connection.db.insert(oauthAuthCodes).values({
      codeHash: hashAuthCode(code),
      clientId: input.clientId,
      userId: input.userId,
      redirectUri: input.redirectUri,
      scopes: [...input.scopes],
      codeChallenge: input.codeChallenge ?? null,
      codeChallengeMethod: input.codeChallengeMethod ?? null,
      expiresAt: sql`now() + ${this.ttlSeconds} * interval '1 second'`,
    });
    return code;
  }

  async consume(code: string, clientId: string): Promise<OAuthCodeRecord | null> {
    const rows = await this.connection.db
      .update(oauthAuthCodes)
      .set({ consumedAt: sql`now()` })
      .where(
        and(
          eq(oauthAuthCodes.codeHash, hashAuthCode(code)),
          eq(oauthAuthCodes.clientId, clientId),
          isNull(oauthAuthCodes.consumedAt),
          gt(oauthAuthCodes.expiresAt, sql`now()`),
        ),
      )
      .returning();
    const row = rows[0];
    if (!row) return null;
    return {
      clientId: row.clientId,
      userId: row.userId,
      redirectUri: row.redirectUri,
      scopes: row.scopes,
      codeChallenge: row.codeChallenge,
      codeChallengeMethod: row.codeChallengeMethod,
    };
  }
}
