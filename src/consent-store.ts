import type { DatabaseConnection } from '@framework/database';
import { and, eq } from 'drizzle-orm';
import { oauthConsents } from './schema/tables';
import type { OAuthConsentStore } from './types';

/**
 * PostgreSQL-backed consent records, one row per user+client. `grant` upserts
 * so re-consenting replaces the approved set; `revoke` deletes the row so the
 * next authorization request shows the consent screen again.
 */
export class PgOAuthConsentStore implements OAuthConsentStore {
  constructor(private readonly connection: DatabaseConnection) {}

  async grantedScopes(userId: string, clientId: string): Promise<readonly string[]> {
    const rows = await this.connection.db
      .select({ scopes: oauthConsents.scopes })
      .from(oauthConsents)
      .where(and(eq(oauthConsents.userId, userId), eq(oauthConsents.clientId, clientId)))
      .limit(1);
    return rows[0]?.scopes ?? [];
  }

  async grant(userId: string, clientId: string, scopes: readonly string[]): Promise<void> {
    await this.connection.db
      .insert(oauthConsents)
      .values({ userId, clientId, scopes: [...scopes] })
      .onConflictDoUpdate({
        target: [oauthConsents.userId, oauthConsents.clientId],
        set: { scopes: [...scopes] },
      });
  }

  async revoke(userId: string, clientId: string): Promise<void> {
    await this.connection.db
      .delete(oauthConsents)
      .where(and(eq(oauthConsents.userId, userId), eq(oauthConsents.clientId, clientId)));
  }
}
