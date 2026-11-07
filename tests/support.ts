import type { Principal } from '@framework/auth';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import { generateKeyPair } from 'jose';
import { PgOAuthClientStore } from '../src/client-store';
import { PgOAuthCodeStore } from '../src/code-store';
import { defaultOAuthServerConfig } from '../src/config-schema';
import { PgOAuthConsentStore } from '../src/consent-store';
import { defaultOAuthGrants } from '../src/grants';
import { InMemoryScopeRegistry } from '../src/scopes';
import { DefaultAuthorizationServer } from '../src/server';
import { JwtTokenIssuer } from '../src/token-issuer';
import { PgOAuthTokenStore } from '../src/token-store';
import type { GrantHandler, OAuthClient, OAuthGrantType, OAuthServerConfig, Scope } from '../src/types';

/** Shared across the oauth-server test files (one isolated database per file). */
export const ISSUER = 'https://auth.example';
export const AUDIENCE = 'api';
export const REDIRECT_URI = 'https://app.example/callback';

/** `exp` claim (unix seconds) `seconds` in the future. */
export const expIn = (seconds: number): number => Math.floor(Date.now() / 1000) + seconds;
/** A `Date` `seconds` from now. */
export const dateIn = (seconds: number): Date => new Date(Date.now() + seconds * 1000);

/** Every registered scope of the fixture's registry. */
export const FIXTURE_SCOPES: readonly Scope[] = [
  { name: 'profile', description: 'Read the profile' },
  { name: 'notes.read', description: 'Read notes', implies: ['notes.read.public'] },
  { name: 'notes.read.public', description: 'Read public notes' },
];

export interface OAuthFixture {
  readonly database: TestDatabase;
  readonly connection: DatabaseConnection;
  readonly config: OAuthServerConfig;
  readonly scopes: InMemoryScopeRegistry;
  readonly clients: PgOAuthClientStore;
  readonly codes: PgOAuthCodeStore;
  readonly tokens: PgOAuthTokenStore;
  readonly consents: PgOAuthConsentStore;
  readonly issuer: JwtTokenIssuer;
  readonly server: DefaultAuthorizationServer;
  /** Registers a client of the given type; confidential clients also return the secret. */
  registerClient(
    type: 'confidential' | 'public',
    overrides?: Partial<{
      readonly allowedGrants: readonly OAuthGrantType[];
      readonly allowedScopes: readonly string[];
    }>,
  ): Promise<{ readonly client: OAuthClient; readonly secret?: string }>;
  /** Inserts a framework `users` row; returns its id (the OAuth subject). */
  registerUser(): Promise<string>;
  /** A server bound to a subset of grants (unsupported-grant-type coverage). */
  serverWithGrants(grants: readonly GrantHandler[]): DefaultAuthorizationServer;
}

/**
 * Boots an isolated test database with the OAuth schema (package-level tests
 * own their tables, mirroring the existing `introspection.test.ts` setup),
 * wires the production stores and a `DefaultAuthorizationServer` around them.
 */
export async function createOAuthFixture(): Promise<OAuthFixture> {
  const database = await createTestDatabase({ adminUrl: requireTestDatabaseUrl() });
  const connection = createConnection({ url: database.url, maxConnections: 2 });
  await connection.sql`
    create table users (
      id uuid primary key default gen_random_uuid(),
      name text not null,
      email text not null unique,
      email_verified_at timestamptz,
      password_hash text not null,
      totp_secret text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`
    create table oauth_clients (
      id text primary key,
      name text not null,
      type text not null,
      redirect_uris text[] not null,
      allowed_grants text[] not null,
      allowed_scopes text[] not null,
      secret_hash text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`
    create table oauth_auth_codes (
      id uuid primary key default gen_random_uuid(),
      code_hash text not null unique,
      client_id text not null references oauth_clients(id) on delete cascade,
      user_id uuid not null references users(id) on delete cascade,
      redirect_uri text not null,
      scopes text[] not null,
      code_challenge text,
      code_challenge_method text,
      expires_at timestamptz not null,
      consumed_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`
    create table oauth_access_tokens (
      id uuid primary key default gen_random_uuid(),
      token_hash text not null unique,
      client_id text not null references oauth_clients(id) on delete cascade,
      user_id uuid references users(id) on delete cascade,
      scopes text[] not null,
      expires_at timestamptz not null,
      revoked_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`
    create table oauth_refresh_tokens (
      id uuid primary key default gen_random_uuid(),
      token_hash text not null unique,
      client_id text not null references oauth_clients(id) on delete cascade,
      user_id uuid references users(id) on delete cascade,
      scopes text[] not null,
      expires_at timestamptz not null,
      revoked_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`
    create table oauth_consents (
      id uuid primary key default gen_random_uuid(),
      user_id uuid not null references users(id) on delete cascade,
      client_id text not null references oauth_clients(id) on delete cascade,
      scopes text[] not null,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      constraint oauth_consents_user_client_key unique (user_id, client_id))`;

  const config: OAuthServerConfig = { ...defaultOAuthServerConfig, issuer: ISSUER, audience: AUDIENCE };
  const scopes = new InMemoryScopeRegistry(FIXTURE_SCOPES);
  const clients = new PgOAuthClientStore(connection);
  const codes = new PgOAuthCodeStore(connection, config.authCodeTtlSeconds);
  const tokens = new PgOAuthTokenStore(connection);
  const consents = new PgOAuthConsentStore(connection);
  const signingKeys = await generateKeyPair('RS256', { extractable: true });
  const issuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE, keys: signingKeys });

  const deps = { clients, codes, tokens, consents, scopes, issuer, config, grants: defaultOAuthGrants() };
  const server = new DefaultAuthorizationServer(deps);

  return {
    database,
    connection,
    config,
    scopes,
    clients,
    codes,
    tokens,
    consents,
    issuer,
    server,
    async registerClient(type, overrides) {
      return clients.register({
        name: `${type} app`,
        type,
        redirectUris: [REDIRECT_URI],
        allowedGrants: overrides?.allowedGrants ?? ['authorization_code', 'refresh_token', 'client_credentials'],
        allowedScopes: overrides?.allowedScopes ?? ['profile', 'notes.read'],
      });
    },
    async registerUser() {
      const id = crypto.randomUUID();
      await connection.sql`
        insert into users (id, name, email, password_hash)
        values (${id}, 'Fixture User', ${`user-${id}@example.test`}, 'x')`;
      return id;
    },
    serverWithGrants(grants) {
      return new DefaultAuthorizationServer({ ...deps, grants: [...grants] });
    },
  };
}

/** Closes the connection and drops the database; safe to call once per fixture. */
export async function dropOAuthFixture(fixture: OAuthFixture): Promise<void> {
  await fixture.connection.close();
  await fixture.database.drop();
}

/** The session principal shape the authorization endpoint consumes (only `.id` is read). */
export const principalFor = (userId: string): Principal =>
  ({ id: userId, via: 'session', abilities: ['*'] }) as unknown as Principal;

/** Reads the query parameters of a redirect target. */
export const queryOf = (url: string): URLSearchParams => new URL(url).searchParams;
