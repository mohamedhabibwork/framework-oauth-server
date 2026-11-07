import { users } from '@framework/auth';
import type { InferSelectModel } from 'drizzle-orm';
import { index, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';

/** `timestamptz` in `date` mode so the stores can hand typed `Date`s to callers. */
const createdAtColumn = () => timestamp('created_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow();
const updatedAtColumn = () =>
  timestamp('updated_at', { withTimezone: true, mode: 'date' })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date());

/**
 * Registered OAuth clients. The `client_secret` is never stored: confidential
 * clients keep only its SHA-256 hash, and public clients (which must use PKCE)
 * have none at all.
 */
export const oauthClients = pgTable('oauth_clients', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  /** `'confidential' | 'public'` (validated in the store, not FK-enforced). */
  type: text('type').notNull(),
  redirectUris: text('redirect_uris').array().notNull(),
  allowedGrants: text('allowed_grants').array().notNull(),
  allowedScopes: text('allowed_scopes').array().notNull(),
  /** SHA-256 hex; null for public clients. */
  secretHash: text('secret_hash'),
  createdAt: createdAtColumn(),
  updatedAt: updatedAtColumn(),
});

/**
 * Single-use authorization codes. Only the SHA-256 hash is stored; `consumedAt`
 * makes every code single-use — a replay misses the SQL guard and resolves to
 * nothing. `codeChallenge` carries the PKCE challenge for public clients.
 */
export const oauthAuthCodes = pgTable(
  'oauth_auth_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    codeHash: text('code_hash').notNull().unique(),
    clientId: text('client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    redirectUri: text('redirect_uri').notNull(),
    scopes: text('scopes').array().notNull(),
    codeChallenge: text('code_challenge'),
    codeChallengeMethod: text('code_challenge_method'),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
    consumedAt: timestamp('consumed_at', { withTimezone: true, mode: 'date' }),
    createdAt: createdAtColumn(),
    updatedAt: updatedAtColumn(),
  },
  (table) => [index('oauth_auth_codes_client_id_idx').on(table.clientId)],
);

/** Opaque access tokens; only the SHA-256 hash is stored. */
export const oauthAccessTokens = pgTable(
  'oauth_access_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tokenHash: text('token_hash').notNull().unique(),
    clientId: text('client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    /** Null for client-credentials tokens (there is no end user). */
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    scopes: text('scopes').array().notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true, mode: 'date' }),
    createdAt: createdAtColumn(),
    updatedAt: updatedAtColumn(),
  },
  (table) => [
    index('oauth_access_tokens_client_id_idx').on(table.clientId),
    index('oauth_access_tokens_user_id_idx').on(table.userId),
  ],
);

/** Opaque refresh tokens; only the SHA-256 hash is stored. */
export const oauthRefreshTokens = pgTable(
  'oauth_refresh_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tokenHash: text('token_hash').notNull().unique(),
    clientId: text('client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    scopes: text('scopes').array().notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true, mode: 'date' }),
    createdAt: createdAtColumn(),
    updatedAt: updatedAtColumn(),
  },
  (table) => [
    index('oauth_refresh_tokens_client_id_idx').on(table.clientId),
    index('oauth_refresh_tokens_user_id_idx').on(table.userId),
  ],
);

/** Per user+client consent: the scopes a user approved for a client. */
export const oauthConsents = pgTable(
  'oauth_consents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    clientId: text('client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    scopes: text('scopes').array().notNull(),
    createdAt: createdAtColumn(),
    updatedAt: updatedAtColumn(),
  },
  (table) => [uniqueIndex('oauth_consents_user_client_idx').on(table.userId, table.clientId)],
);

export type OAuthClientRow = InferSelectModel<typeof oauthClients>;
export type OAuthAuthCodeRow = InferSelectModel<typeof oauthAuthCodes>;
export type OAuthAccessTokenRow = InferSelectModel<typeof oauthAccessTokens>;
export type OAuthRefreshTokenRow = InferSelectModel<typeof oauthRefreshTokens>;
export type OAuthConsentRow = InferSelectModel<typeof oauthConsents>;
