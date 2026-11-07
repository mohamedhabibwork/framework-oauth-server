import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createJwtPrincipalResolver, DatabaseUserProvider } from '@framework/auth';
import { createConnection, type DatabaseConnection } from '@framework/database';
import {
  createTestDatabase,
  requireTestDatabaseUrl,
  serveOnEphemeralPort,
  type TestDatabase,
} from '@framework/testing';
import { generateKeyPair } from 'jose';
import { JwtTokenIssuer } from '../src';

/**
 * The load-bearing ADR-16 claim: a token minted by `JwtTokenIssuer` is accepted
 * by the **existing** `@framework/auth` jwt guard, with no new verification
 * code — because the issuer signs with `jose` and publishes the JWKS the guard
 * already knows how to consume. This file proves it end to end from the
 * resource server's side, so the reuse is validated engineering rather than
 * design intent.
 */
const ISSUER = 'https://auth.example';
const AUDIENCE = 'api';
const USER_ID = '00000000-0000-4000-8000-0000000000a1';
const SCOPES = ['notes.read', 'profile'] as const;

/** `exp` claim (unix seconds) `seconds` in the future. */
const expIn = (seconds: number): number => Math.floor(Date.now() / 1000) + seconds;

/** Claims a grant would build before asking the issuer for an access token. */
const claimsFor = (clientId: string, scopes: readonly string[]) => ({
  sub: USER_ID,
  clientId,
  scopes,
  expiresAt: expIn(600),
  issuer: ISSUER,
  audience: AUDIENCE,
});

let database: TestDatabase;
let connection: DatabaseConnection;
/** The OAuth server's own signing key pair, published as its JWKS. */
let signingKeys: CryptoKeyPair;
let issuer: JwtTokenIssuer;
/** A real JWKS endpoint over HTTP — the production shape (rotation-aware). */
let jwksServer: ReturnType<typeof serveOnEphemeralPort>;

beforeAll(async () => {
  database = await createTestDatabase({ adminUrl: requireTestDatabaseUrl() });
  connection = createConnection({ url: database.url, maxConnections: 2 });
  // The guard resolves `sub` against the framework's own `users` table.
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
    insert into users (id, name, email, password_hash)
    values (${USER_ID}, 'OAuth User', 'oauth@example.test', 'x')`;

  signingKeys = await generateKeyPair('RS256', { extractable: true });
  issuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE, keys: signingKeys });

  const jwks = await issuer.jwks();
  jwksServer = serveOnEphemeralPort(
    () => new Response(JSON.stringify(jwks), { headers: { 'content-type': 'application/json' } }),
  );
});

afterAll(async () => {
  await jwksServer.stop();
  await connection.close();
  await database.drop();
});

describe('ADR-16: the framework jwt guard verifies OAuth access tokens', () => {
  test('a token minted by JwtTokenIssuer resolves the local user via inline JWKS', async () => {
    const resolveJwt = createJwtPrincipalResolver({
      config: { jwksUri: '', issuer: ISSUER, audience: AUDIENCE },
      keys: { jwks: await issuer.jwks() },
      users: new DatabaseUserProvider(connection),
    });
    const token = await issuer.issue(claimsFor('client-1', SCOPES));

    const principal = await resolveJwt(`Bearer ${token}`);
    expect(principal?.id).toBe(USER_ID);
    expect(principal?.via).toBe('jwt');
    // The space-delimited `scope` claim becomes the principal's abilities.
    expect(principal?.abilities).toEqual([...SCOPES]);
  });

  test('the same token verifies against a remote JWKS endpoint (jwksUri)', async () => {
    const resolveJwt = createJwtPrincipalResolver({
      config: { jwksUri: jwksServer.baseUrl, issuer: ISSUER, audience: AUDIENCE },
      // The guard takes the *key source* from `keys`; `config.jwt.jwksUri` is the
      // app-level mirror of it. `cooldownDurationMs: 0` keeps rotation immediate.
      keys: { jwksUri: jwksServer.baseUrl, cooldownDurationMs: 0 },
      users: new DatabaseUserProvider(connection),
    });
    const token = await issuer.issue(claimsFor('client-1', SCOPES));

    const principal = await resolveJwt(`Bearer ${token}`);
    expect(principal?.id).toBe(USER_ID);
    expect(principal?.abilities).toEqual([...SCOPES]);
  });

  test('a token without any scope claim grants * like a session principal', async () => {
    const resolveJwt = createJwtPrincipalResolver({
      config: { jwksUri: '', issuer: ISSUER, audience: AUDIENCE },
      keys: { jwks: await issuer.jwks() },
      users: new DatabaseUserProvider(connection),
    });
    const token = await issuer.issue(claimsFor('client-1', []));

    expect((await resolveJwt(`Bearer ${token}`))?.abilities).toEqual(['*']);
  });

  test('bad signature, wrong audience and wrong issuer are all rejected', async () => {
    const resolveJwt = createJwtPrincipalResolver({
      config: { jwksUri: '', issuer: ISSUER, audience: AUDIENCE },
      keys: { jwks: await issuer.jwks() },
      users: new DatabaseUserProvider(connection),
    });
    const tokens = claimsFor('client-1', SCOPES);

    // Bad signature: foreign key published under the same `kid`.
    const forgedIssuer = await JwtTokenIssuer.create({ issuer: ISSUER, audience: AUDIENCE });
    // Wrong audience / wrong issuer: our key, but signed for someone else.
    const wrongAudience = await JwtTokenIssuer.create({ issuer: ISSUER, audience: 'other-api', keys: signingKeys });
    const wrongIssuer = await JwtTokenIssuer.create({
      issuer: 'https://evil.example',
      audience: AUDIENCE,
      keys: signingKeys,
    });

    expect(await resolveJwt(`Bearer ${await forgedIssuer.issue(tokens)}`)).toBeNull();
    expect(await resolveJwt(`Bearer ${await wrongAudience.issue(tokens)}`)).toBeNull();
    expect(await resolveJwt(`Bearer ${await wrongIssuer.issue(tokens)}`)).toBeNull();
    // Garbage, a non-Bearer scheme and a missing header take the 401 path too.
    expect(await resolveJwt('Bearer not.a.jwt')).toBeNull();
    expect(await resolveJwt('Basic dXNlcjpwYXNz')).toBeNull();
    expect(await resolveJwt(undefined)).toBeNull();
  });

  test('a subject with no local user stays anonymous (JWTs never provision accounts)', async () => {
    const resolveJwt = createJwtPrincipalResolver({
      config: { jwksUri: '', issuer: ISSUER, audience: AUDIENCE },
      keys: { jwks: await issuer.jwks() },
      users: new DatabaseUserProvider(connection),
    });
    // Correct signature, same issuer/audience — but the subject has no `users` row.
    const token = await issuer.issue({ ...claimsFor('client-1', SCOPES), sub: '00000000-0000-4000-8000-0000000000ff' });

    expect(await resolveJwt(`Bearer ${token}`)).toBeNull();
  });
});
