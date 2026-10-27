import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createJwtPrincipalResolver, DatabaseUserProvider } from '@framework/auth';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import { generateKeyPair } from 'jose';
import {
  expandScopes,
  InMemoryScopeRegistry,
  introspectToken,
  JwtTokenIssuer,
  OpaqueTokenIssuer,
  PgOAuthClientStore,
  PgOAuthCodeStore,
  PgOAuthConsentStore,
  PgOAuthTokenStore,
} from '../src';

const ISSUER = 'https://auth.example';
const AUDIENCE = 'api';
const USER_ID = '00000000-0000-4000-8000-0000000000a1';
const REDIRECT_URI = 'https://app.example/callback';

let database: TestDatabase;
let connection: DatabaseConnection;

/** `exp` claim (unix seconds) `seconds` in the future. */
const expIn = (seconds: number): number => Math.floor(Date.now() / 1000) + seconds;
const dateIn = (seconds: number): Date => new Date(Date.now() + seconds * 1000);

/** Registers a fresh client of the given type; returns the store row + secret. */
const registerClient = async (type: 'confidential' | 'public') =>
  new PgOAuthClientStore(connection).register({
    name: `${type} app`,
    type,
    redirectUris: [REDIRECT_URI],
    allowedGrants: ['authorization_code', 'refresh_token', 'client_credentials'],
    allowedScopes: ['profile', 'notes.read'],
  });

beforeAll(async () => {
  database = await createTestDatabase({ adminUrl: requireTestDatabaseUrl() });
  connection = createConnection({ url: database.url, maxConnections: 2 });
  // Package-level tests own their schema (mirrors packages/auth/tests): the
  // framework `users` table plus the OAuth tables, created with raw DDL.
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
  await connection.sql`
    insert into users (id, name, email, password_hash)
    values (${USER_ID}, 'OAuth User', 'oauth@example.test', 'x')`;
});

afterAll(async () => {
  await connection.close();
  await database.drop();
});

describe('JwtTokenIssuer (jose / framework JWKS)', () => {
  test('round-trips claims and is accepted by the framework jwt guard (ADR-16)', async () => {
    const issuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE });
    const claims = {
      sub: USER_ID,
      clientId: 'client-1',
      scopes: ['notes.read', 'profile'],
      expiresAt: expIn(600),
      issuer: ISSUER,
      audience: AUDIENCE,
    };
    const token = await issuer.issue(claims);

    expect(await issuer.verify(token)).toEqual(claims);

    // The existing @framework/auth guard verifies it against the issuer's JWKS
    // with no new code — the `scope` claim becomes the principal's abilities.
    const resolveJwt = createJwtPrincipalResolver({
      config: { jwksUri: '', issuer: ISSUER, audience: AUDIENCE },
      keys: { jwks: await issuer.jwks() },
      users: new DatabaseUserProvider(connection),
    });
    const principal = await resolveJwt(`Bearer ${token}`);
    expect(principal?.id).toBe(USER_ID);
    expect(principal?.via).toBe('jwt');
    expect(principal?.abilities).toEqual(['notes.read', 'profile']);
  });

  test('rejects a wrong audience, a wrong issuer and tokens from a foreign key', async () => {
    const keys = await generateKeyPair('RS256', { extractable: true });
    const issuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE, keys });
    // Same signing key, different expectations: isolates the iss/aud checks.
    const wrongAudience = await JwtTokenIssuer.create({ issuer: ISSUER, audience: 'other-api', keys });
    const wrongIssuer = await JwtTokenIssuer.create({ issuer: 'https://evil.example', audience: AUDIENCE, keys });
    const foreign = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE });
    const claims = {
      sub: USER_ID,
      clientId: 'c',
      scopes: [],
      expiresAt: expIn(600),
      issuer: ISSUER,
      audience: AUDIENCE,
    };

    expect(await issuer.verify(await wrongAudience.issue(claims))).toBeNull();
    expect(await issuer.verify(await wrongIssuer.issue(claims))).toBeNull();
    expect(await issuer.verify(await foreign.issue(claims))).toBeNull();
    expect(await issuer.verify('not.a.jwt')).toBeNull();
  });
});

describe('OpaqueTokenIssuer + PgOAuthTokenStore', () => {
  test('issues, verifies, revokes and prunes', async () => {
    const { client } = await registerClient('confidential');
    const tokens = new PgOAuthTokenStore(connection);
    const issuer = new OpaqueTokenIssuer({ tokens, issuer: ISSUER, audience: AUDIENCE });
    const token = await issuer.issue({
      sub: USER_ID,
      clientId: client.id,
      scopes: ['notes.read'],
      expiresAt: expIn(600),
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    const verified = await issuer.verify(token);
    expect(verified?.sub).toBe(USER_ID);
    expect(verified?.clientId).toBe(client.id);
    expect(verified?.scopes).toEqual(['notes.read']);

    expect(await tokens.revoke(token)).toBe(true);
    expect(await issuer.verify(token)).toBeNull();
    expect(await tokens.revoke(token)).toBe(false);

    await tokens.issueAccess({ clientId: client.id, userId: null, scopes: ['x'], expiresAt: dateIn(-1) });
    expect(await tokens.prune()).toBeGreaterThanOrEqual(1);
  });

  test('revokeAllForUser revokes access and refresh tokens together', async () => {
    const { client } = await registerClient('confidential');
    const tokens = new PgOAuthTokenStore(connection);
    await tokens.issueAccess({ clientId: client.id, userId: USER_ID, scopes: [], expiresAt: dateIn(600) });
    await tokens.issueRefresh({ clientId: client.id, userId: USER_ID, scopes: [], expiresAt: dateIn(600) });
    expect(await tokens.revokeAllForUser(USER_ID)).toBeGreaterThanOrEqual(2);
  });
});

describe('introspectToken (RFC 7662)', () => {
  test('a valid JWT is active and reports scope, client_id, sub and exp', async () => {
    const issuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE });
    const token = await issuer.issue({
      sub: USER_ID,
      clientId: 'client-1',
      scopes: ['profile', 'notes.read'],
      expiresAt: expIn(600),
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    expect(await introspectToken(token, issuer)).toEqual({
      active: true,
      scope: 'profile notes.read',
      clientId: 'client-1',
      sub: USER_ID,
      exp: expect.any(Number),
    });
  });

  test('a client-credentials JWT (no subject) is active without a sub', async () => {
    const issuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE });
    const token = await issuer.issue({
      sub: null,
      clientId: 'service-client',
      scopes: ['jobs.run'],
      expiresAt: expIn(60),
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    const result = await introspectToken(token, issuer);
    expect(result.active).toBe(true);
    expect(result.scope).toBe('jobs.run');
    expect(result.sub).toBeUndefined();
  });

  test('an opaque token introspects through its issuer; a revoked one is inactive', async () => {
    const { client } = await registerClient('confidential');
    const tokens = new PgOAuthTokenStore(connection);
    const issuer = new OpaqueTokenIssuer({ tokens, issuer: ISSUER, audience: AUDIENCE });
    const token = await issuer.issue({
      sub: USER_ID,
      clientId: client.id,
      scopes: ['notes.read'],
      expiresAt: expIn(600),
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    expect((await introspectToken(token, issuer)).active).toBe(true);
    await tokens.revoke(token);
    expect(await introspectToken(token, issuer)).toEqual({ active: false });
  });

  test('garbage and tampered tokens are inactive', async () => {
    const issuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE });
    expect(await introspectToken('not-a-token', issuer)).toEqual({ active: false });
    const token = await issuer.issue({
      sub: USER_ID,
      clientId: 'c',
      scopes: [],
      expiresAt: expIn(600),
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    expect(await introspectToken(`${token}tampered`, issuer)).toEqual({ active: false });
  });
});

describe('PgOAuthClientStore', () => {
  test('stores a confidential secret hashed, never in the clear', async () => {
    const store = new PgOAuthClientStore(connection);
    const { client, secret } = await store.register({
      name: 'confidential app',
      type: 'confidential',
      redirectUris: [REDIRECT_URI],
      allowedGrants: ['authorization_code'],
      allowedScopes: ['profile'],
    });
    if (!secret) throw new Error('a confidential client must receive a secret');

    expect(client.secretHash).toBeTruthy();
    expect(client.secretHash).not.toBe(secret);
    expect(client.secretHash).not.toContain(secret);
    expect(await store.verifySecret(client.id, secret)).toBe(true);
    expect(await store.verifySecret(client.id, 'wrong-secret')).toBe(false);

    const found = await store.find(client.id);
    expect(found?.secretHash).toBe(client.secretHash);
    expect(await store.list()).toContainEqual(expect.objectContaining({ id: client.id }));
  });

  test('public clients have no secret and never verify (PKCE-only)', async () => {
    const store = new PgOAuthClientStore(connection);
    const { client, secret } = await store.register({
      name: 'public app',
      type: 'public',
      redirectUris: [REDIRECT_URI],
      allowedGrants: ['authorization_code'],
      allowedScopes: ['profile'],
    });

    expect(secret).toBeUndefined();
    expect(client.secretHash).toBeUndefined();
    expect(await store.verifySecret(client.id, 'anything')).toBe(false);
    expect(await store.find('missing-client')).toBeNull();
  });
});

describe('PgOAuthCodeStore', () => {
  test('codes are single-use and carry the PKCE challenge', async () => {
    const { client } = await registerClient('public');
    const codes = new PgOAuthCodeStore(connection, 60);
    const code = await codes.issue({
      clientId: client.id,
      userId: USER_ID,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
      codeChallenge: 'challenge-abc',
      codeChallengeMethod: 'S256',
    });

    expect(await codes.consume(code, client.id)).toMatchObject({
      clientId: client.id,
      userId: USER_ID,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
      codeChallenge: 'challenge-abc',
      codeChallengeMethod: 'S256',
    });
    // A replay finds the code already consumed.
    expect(await codes.consume(code, client.id)).toBeNull();
  });

  test('a code is refused for the wrong client and once expired', async () => {
    const { client } = await registerClient('confidential');
    const other = await registerClient('confidential');
    const codes = new PgOAuthCodeStore(connection, 60);
    const code = await codes.issue({ clientId: client.id, userId: USER_ID, redirectUri: REDIRECT_URI, scopes: [] });
    expect(await codes.consume(code, other.client.id)).toBeNull();
    expect(await codes.consume(code, client.id)).not.toBeNull();

    // A non-positive TTL issues an already-expired code.
    const expired = await new PgOAuthCodeStore(connection, -1).issue({
      clientId: client.id,
      userId: USER_ID,
      redirectUri: REDIRECT_URI,
      scopes: [],
    });
    expect(await codes.consume(expired, client.id)).toBeNull();
  });
});

describe('PgOAuthConsentStore', () => {
  test('grant upserts the approved scopes and revoke clears them', async () => {
    const { client } = await registerClient('confidential');
    const consents = new PgOAuthConsentStore(connection);
    expect(await consents.grantedScopes(USER_ID, client.id)).toEqual([]);

    await consents.grant(USER_ID, client.id, ['profile', 'notes.read']);
    expect(await consents.grantedScopes(USER_ID, client.id)).toEqual(['profile', 'notes.read']);

    await consents.grant(USER_ID, client.id, ['profile']);
    expect(await consents.grantedScopes(USER_ID, client.id)).toEqual(['profile']);

    await consents.revoke(USER_ID, client.id);
    expect(await consents.grantedScopes(USER_ID, client.id)).toEqual([]);
  });
});

describe('InMemoryScopeRegistry', () => {
  test('reports unknown names and expands implied scopes', () => {
    const registry = new InMemoryScopeRegistry([
      { name: 'read', description: 'Read anything', implies: ['read:public'] },
      { name: 'read:public', description: 'Read public data' },
    ]);

    expect(registry.validate(['read', 'write'])).toEqual(['write']);
    expect(registry.all().map((scope) => scope.name)).toEqual(['read', 'read:public']);
    expect(expandScopes(registry, ['read'])).toEqual(['read', 'read:public']);
    expect(expandScopes(registry, ['read:public'])).toEqual(['read:public']);
  });
});
