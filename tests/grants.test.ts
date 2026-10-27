import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { ClientCredentialsGrant } from '../src';
import { OAuthError } from '../src/errors';
import type { IssueCodeInput, TokenRequest } from '../src/types';
import { createOAuthFixture, dropOAuthFixture, type OAuthFixture, REDIRECT_URI } from './support';

let fx: OAuthFixture;

beforeAll(async () => {
  fx = await createOAuthFixture();
});

afterAll(async () => {
  await dropOAuthFixture(fx);
});

/** Issues an authorization code straight through the store (as `authorize` would). */
const issueCode = (fixture: OAuthFixture, input: IssueCodeInput) => fixture.codes.issue(input);

/** Error code + status of a failed token request. */
const failure = async (request: TokenRequest): Promise<{ code: string; status: number }> => {
  try {
    await fx.server.token(request);
  } catch (error) {
    if (error instanceof OAuthError) return { code: error.oauthCode, status: error.status };
    throw error;
  }
  throw new Error('expected the token request to fail');
};

describe('authorization_code grant (RFC 6749 §4.1)', () => {
  test('redeems a code for an access + refresh token pair bound to the user', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    const code = await issueCode(fx, {
      clientId: client.id,
      userId,
      redirectUri: REDIRECT_URI,
      scopes: ['profile', 'notes.read'],
    });

    const response = await fx.server.token({
      grantType: 'authorization_code',
      clientId: client.id,
      clientSecret: secret,
      code,
      redirectUri: REDIRECT_URI,
    });

    expect(response).toMatchObject({ tokenType: 'Bearer', expiresIn: 3600, scope: 'profile notes.read' });
    expect(response.refreshToken).toBeTruthy();
    // The access token is a JWT the framework guard verifies (ADR-16).
    const claims = await fx.issuer.verify(response.accessToken);
    expect(claims).toMatchObject({ sub: userId, clientId: client.id, scopes: ['profile', 'notes.read'] });
  });

  test('a code is single-use: replay, wrong client and redirect mismatch all fail', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const other = await fx.registerClient('confidential');
    const userId = await fx.registerUser();

    // Successful redemption first, then the replay fails.
    const code = await issueCode(fx, { clientId: client.id, userId, redirectUri: REDIRECT_URI, scopes: ['profile'] });
    expect(
      await fx.server.token({ grantType: 'authorization_code', clientId: client.id, clientSecret: secret, code }),
    ).toBeTruthy();
    expect(await failure({ grantType: 'authorization_code', clientId: client.id, clientSecret: secret, code })).toEqual(
      {
        code: 'invalid_grant',
        status: 400,
      },
    );

    // A code issued for one client cannot be redeemed by another.
    const codeForOther = await issueCode(fx, {
      clientId: other.client.id,
      userId,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
    });
    expect(
      await failure({ grantType: 'authorization_code', clientId: client.id, clientSecret: secret, code: codeForOther }),
    ).toEqual({ code: 'invalid_grant', status: 400 });

    // RFC 6749 §4.1.3: redirect_uri must match the authorization request.
    const mismatch = await issueCode(fx, {
      clientId: client.id,
      userId,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
    });
    expect(
      await failure({
        grantType: 'authorization_code',
        clientId: client.id,
        clientSecret: secret,
        code: mismatch,
        redirectUri: 'https://attacker.example/callback',
      }),
    ).toEqual({ code: 'invalid_grant', status: 400 });
  });

  test('requested scopes are narrowed to the granted set, never widened', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    const code = await issueCode(fx, { clientId: client.id, userId, redirectUri: REDIRECT_URI, scopes: ['profile'] });

    const narrowed = await fx.server.token({
      grantType: 'authorization_code',
      clientId: client.id,
      clientSecret: secret,
      code,
      scopes: ['profile'],
    });
    expect(narrowed.scope).toBe('profile');

    const code2 = await issueCode(fx, { clientId: client.id, userId, redirectUri: REDIRECT_URI, scopes: ['profile'] });
    expect(
      await failure({
        grantType: 'authorization_code',
        clientId: client.id,
        clientSecret: secret,
        code: code2,
        scopes: ['profile', 'notes.read'],
      }),
    ).toEqual({ code: 'invalid_scope', status: 400 });
  });

  test('client authentication is enforced: missing, wrong or absent secrets fail', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const publicClient = await fx.registerClient('public');
    const userId = await fx.registerUser();
    const code = await issueCode(fx, { clientId: client.id, userId, redirectUri: REDIRECT_URI, scopes: ['profile'] });

    expect(await failure({ grantType: 'authorization_code', clientId: client.id, code })).toEqual({
      code: 'invalid_client',
      status: 401,
    });
    expect(
      await failure({ grantType: 'authorization_code', clientId: client.id, clientSecret: 'wrong', code }),
    ).toEqual({
      code: 'invalid_client',
      status: 401,
    });
    expect(await failure({ grantType: 'authorization_code', clientId: 'missing', code })).toEqual({
      code: 'invalid_client',
      status: 401,
    });
    expect(await failure({ grantType: 'authorization_code', clientId: client.id, clientSecret: secret })).toEqual({
      code: 'invalid_request',
      status: 400,
    });
    expect(await failure({ grantType: 'authorization_code', clientId: publicClient.client.id, code })).toEqual({
      code: 'invalid_grant',
      status: 400,
    });
  });

  test('a client registered without the authorization_code grant is unauthorized_client', async () => {
    const { client, secret } = await fx.registerClient('confidential', { allowedGrants: ['client_credentials'] });
    const userId = await fx.registerUser();
    const code = await issueCode(fx, { clientId: client.id, userId, redirectUri: REDIRECT_URI, scopes: ['profile'] });

    expect(await failure({ grantType: 'authorization_code', clientId: client.id, clientSecret: secret, code })).toEqual(
      {
        code: 'unauthorized_client',
        status: 400,
      },
    );
  });
});

describe('client_credentials grant (RFC 6749 §4.4)', () => {
  test('issues a subject-less token and never a refresh token', async () => {
    const { client, secret } = await fx.registerClient('confidential');

    const response = await fx.server.token({
      grantType: 'client_credentials',
      clientId: client.id,
      clientSecret: secret,
      scopes: ['notes.read'],
    });

    expect(response.refreshToken).toBeUndefined();
    expect(response.scope).toBe('notes.read');
    expect(await fx.issuer.verify(response.accessToken)).toMatchObject({ sub: null, scopes: ['notes.read'] });
  });

  test('defaults to the client’s full allowed scope set and rejects unknown scopes', async () => {
    const { client, secret } = await fx.registerClient('confidential');

    const defaulted = await fx.server.token({
      grantType: 'client_credentials',
      clientId: client.id,
      clientSecret: secret,
    });
    expect(defaulted.scope).toBe('profile notes.read');

    expect(
      await failure({ grantType: 'client_credentials', clientId: client.id, clientSecret: secret, scopes: ['admin'] }),
    ).toEqual({
      code: 'invalid_scope',
      status: 400,
    });
  });

  test('public clients cannot use the grant (no secret to authenticate with)', async () => {
    const { client } = await fx.registerClient('public');
    expect(await failure({ grantType: 'client_credentials', clientId: client.id })).toEqual({
      code: 'unauthorized_client',
      status: 400,
    });
  });
});

describe('refresh_token grant (RFC 6749 §6)', () => {
  /** Runs the authorization-code flow once to obtain a usable refresh token. */
  const seedRefreshToken = async (): Promise<{ clientId: string; secret?: string; refreshToken: string }> => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    const code = await issueCode(fx, {
      clientId: client.id,
      userId,
      redirectUri: REDIRECT_URI,
      scopes: ['profile', 'notes.read'],
    });
    const response = await fx.server.token({
      grantType: 'authorization_code',
      clientId: client.id,
      clientSecret: secret,
      code,
    });
    if (!response.refreshToken) throw new Error('expected a refresh token');
    return { clientId: client.id, secret, refreshToken: response.refreshToken };
  };

  test('rotates the token: the presented one stops working, the new one works', async () => {
    const seed = await seedRefreshToken();

    const refreshed = await fx.server.token({
      grantType: 'refresh_token',
      clientId: seed.clientId,
      clientSecret: seed.secret,
      refreshToken: seed.refreshToken,
    });
    expect(refreshed.accessToken).toBeTruthy();
    expect(refreshed.refreshToken).not.toBe(seed.refreshToken);

    // Rotation revoked the old token: a replay is invalid_grant.
    expect(
      await failure({
        grantType: 'refresh_token',
        clientId: seed.clientId,
        clientSecret: seed.secret,
        refreshToken: seed.refreshToken,
      }),
    ).toEqual({ code: 'invalid_grant', status: 400 });

    // The new token works in turn.
    const again = await fx.server.token({
      grantType: 'refresh_token',
      clientId: seed.clientId,
      clientSecret: seed.secret,
      refreshToken: refreshed.refreshToken,
    });
    expect(again.scope).toBe('profile notes.read');
  });

  test('a refresh token is bound to its client', async () => {
    const seed = await seedRefreshToken();
    const other = await fx.registerClient('confidential');

    expect(
      await failure({
        grantType: 'refresh_token',
        clientId: other.client.id,
        clientSecret: other.secret,
        refreshToken: seed.refreshToken,
      }),
    ).toEqual({ code: 'invalid_grant', status: 400 });
    // The legitimate client is unaffected by the failed cross-client replay.
    expect(
      await fx.server.token({
        grantType: 'refresh_token',
        clientId: seed.clientId,
        clientSecret: seed.secret,
        refreshToken: seed.refreshToken,
      }),
    ).toMatchObject({ scope: 'profile notes.read' });
  });

  test('scopes narrow on refresh; unknown or expired tokens are invalid_grant', async () => {
    const seed = await seedRefreshToken();
    const narrowed = await fx.server.token({
      grantType: 'refresh_token',
      clientId: seed.clientId,
      clientSecret: seed.secret,
      refreshToken: seed.refreshToken,
      scopes: ['profile'],
    });
    expect(narrowed.scope).toBe('profile');

    expect(
      await failure({
        grantType: 'refresh_token',
        clientId: seed.clientId,
        clientSecret: seed.secret,
        refreshToken: narrowed.refreshToken,
        scopes: ['notes.read'],
      }),
    ).toEqual({ code: 'invalid_scope', status: 400 });

    // A refresh token that is already past its expiry never resolves.
    const { client, secret } = await fx.registerClient('confidential');
    const expired = await fx.tokens.issueRefresh({
      clientId: client.id,
      userId: null,
      scopes: ['profile'],
      expiresAt: new Date(Date.now() - 60_000),
    });
    expect(
      await failure({ grantType: 'refresh_token', clientId: client.id, clientSecret: secret, refreshToken: expired }),
    ).toEqual({
      code: 'invalid_grant',
      status: 400,
    });
    expect(
      await failure({
        grantType: 'refresh_token',
        clientId: seed.clientId,
        clientSecret: seed.secret,
        refreshToken: 'fw_rt_deadbeef',
      }),
    ).toEqual({ code: 'invalid_grant', status: 400 });
  });
});

describe('grant selection', () => {
  test('an unregistered grant type is unsupported_grant_type', async () => {
    const server = fx.serverWithGrants([new ClientCredentialsGrant()]);
    await expect(server.token({ grantType: 'authorization_code', clientId: 'x' })).rejects.toMatchObject({
      oauthCode: 'unsupported_grant_type',
    });
  });

  test('an expired authorization code never redeems', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    const code = await issueCode(fx, { clientId: client.id, userId, redirectUri: REDIRECT_URI, scopes: ['profile'] });
    await fx.connection.sql`update oauth_auth_codes set expires_at = now() - interval '1 second'`;
    expect(await failure({ grantType: 'authorization_code', clientId: client.id, clientSecret: secret, code })).toEqual(
      {
        code: 'invalid_grant',
        status: 400,
      },
    );
  });
});

describe('expiry bookkeeping', () => {
  test('the access token TTL matches the configured lifetime', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const response = await fx.server.token({
      grantType: 'client_credentials',
      clientId: client.id,
      clientSecret: secret,
    });
    const claims = await fx.issuer.verify(response.accessToken);
    const now = Math.floor(Date.now() / 1000);
    expect(claims?.expiresAt).toBeGreaterThan(now);
    expect(claims?.expiresAt).toBeLessThanOrEqual(now + fx.config.accessTokenTtlSeconds);
    expect(response.expiresIn).toBe(fx.config.accessTokenTtlSeconds);
  });
});
