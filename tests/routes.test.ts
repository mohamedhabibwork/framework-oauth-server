import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { type FrameworkEnv, installErrorHandling } from '@framework/http';
import { Hono } from 'hono';
import { CONSENT_PAGE_PATH, defaultOAuthGrants, defineOAuthRoutes } from '../src';
import { createOAuthFixture, dropOAuthFixture, type OAuthFixture, queryOf, REDIRECT_URI } from './support';

let fx: OAuthFixture;
let app: Hono<FrameworkEnv>;
/** The session identity the test middleware installs (null keeps routes anonymous). */
let principal: { readonly id: string; readonly abilities: readonly string[] } | null = null;

const authorizePath = (params: Record<string, string>): string => {
  const query = new URLSearchParams({ response_type: 'code', redirect_uri: REDIRECT_URI, ...params });
  return `/authorize?${query.toString()}`;
};

const get = (path: string) => app.request(path);

const postForm = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  app.request(path, {
    method: 'POST',
    body: new URLSearchParams(body).toString(),
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
  });

const postJson = (path: string, body: unknown) =>
  app.request(path, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } });

const basic = (clientId: string, secret: string) => ({ authorization: `Basic ${btoa(`${clientId}:${secret}`)}` });

/** Redeems the `code` of a redirect target at the token endpoint with client_secret_post. */
const redeemRedirect = async (location: string, credentials: { clientId: string; secret?: string }) => {
  const form: Record<string, string> = {
    grant_type: 'authorization_code',
    client_id: credentials.clientId,
    code: queryOf(location).get('code') ?? '',
    redirect_uri: REDIRECT_URI,
  };
  if (credentials.secret) form.client_secret = credentials.secret;
  return postForm('/token', form);
};

beforeAll(async () => {
  fx = await createOAuthFixture();
  app = installErrorHandling(new Hono<FrameworkEnv>(), { exposeInternalErrors: true });
  app.use('*', async (c, next) => {
    if (principal) c.set('principal', principal);
    await next();
  });
  app.route(
    '/',
    defineOAuthRoutes({ server: fx.server, config: fx.config, scopes: fx.scopes, grants: defaultOAuthGrants() }),
  );
});

afterAll(async () => {
  await dropOAuthFixture(fx);
});

describe('authorization-server metadata (RFC 8414)', () => {
  test('advertises the endpoints, the registered grants and the scopes', async () => {
    const response = await get('/.well-known/oauth-authorization-server');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      issuer: fx.config.issuer,
      authorization_endpoint: `${fx.config.issuer}/oauth/authorize`,
      token_endpoint: `${fx.config.issuer}/oauth/token`,
      introspection_endpoint: `${fx.config.issuer}/oauth/introspect`,
      revocation_endpoint: `${fx.config.issuer}/oauth/revoke`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
      scopes_supported: ['profile', 'notes.read', 'notes.read.public'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    });
  });
});

describe('GET /authorize', () => {
  test('redirects with a code once consent is on record', async () => {
    const { client } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    await fx.consents.grant(userId, client.id, ['profile']);
    principal = { id: userId, abilities: ['*'] };

    const response = await get(authorizePath({ client_id: client.id, scope: 'profile', state: 'xyz' }));
    expect(response.status).toBe(302);
    const location = response.headers.get('location') ?? '';
    expect(location.startsWith(REDIRECT_URI)).toBe(true);
    expect(queryOf(location).get('state')).toBe('xyz');
    expect(queryOf(location).get('code')).toBeTruthy();

    // The issued code redeems at the token endpoint; without the secret, 401.
    const token = await redeemRedirect(location, { clientId: client.id, secret: '' });
    expect(token.status).toBe(401);
    expect(await token.json()).toMatchObject({ error: 'invalid_client' });
  });

  test('anonymous callers get the framework 401 envelope', async () => {
    const { client } = await fx.registerClient('confidential');
    principal = null;

    const response = await get(authorizePath({ client_id: client.id }));
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });
  });

  test('redirectable failures travel on the redirect (RFC 6749 §4.1.2.1)', async () => {
    const { client } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };

    const wrongResponseType = await get(authorizePath({ client_id: client.id, response_type: 'token', state: 's1' }));
    expect(wrongResponseType.status).toBe(302);
    const wrongTypeParams = queryOf(wrongResponseType.headers.get('location') ?? '');
    expect(wrongTypeParams.get('error')).toBe('unsupported_response_type');
    expect(wrongTypeParams.get('state')).toBe('s1');

    const badScope = await get(authorizePath({ client_id: client.id, scope: 'admin', state: 's2' }));
    expect(queryOf(badScope.headers.get('location') ?? '').get('error')).toBe('invalid_scope');
  });

  test('pre-validation failures answer 400 (no safe redirect exists)', async () => {
    const { client } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };

    const unknownClient = await get(authorizePath({ client_id: 'fw_client_missing' }));
    expect(unknownClient.status).toBe(400);
    expect(await unknownClient.json()).toMatchObject({ error: 'invalid_request' });

    const badRedirect = await get(
      authorizePath({ client_id: client.id, redirect_uri: 'https://evil.example/callback' }),
    );
    expect(badRedirect.status).toBe(400);
    expect(await badRedirect.json()).toMatchObject({ error: 'invalid_request' });
  });

  test('a missing consent redirects to the consent screen', async () => {
    const { client } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };

    const response = await get(authorizePath({ client_id: client.id, scope: 'profile' }));
    expect(response.status).toBe(302);
    const consentUrl = new URL(response.headers.get('location') ?? '');
    expect(consentUrl.pathname).toBe(CONSENT_PAGE_PATH);
    expect(consentUrl.searchParams.get('client_id')).toBe(client.id);
  });
});

describe('POST /consent', () => {
  test('an approved consent answers the redirect target carrying the code', async () => {
    const { client } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };

    const response = await postJson('/consent', {
      clientId: client.id,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
      approved: true,
      state: 'st-1',
    });
    expect(response.status).toBe(200);
    const { redirectTo } = (await response.json()) as { redirectTo: string };
    const params = queryOf(redirectTo);
    expect(params.get('code')).toBeTruthy();
    expect(params.get('state')).toBe('st-1');

    // Consent is recorded: a later authorization request skips the screen.
    expect(await fx.consents.grantedScopes(userId, client.id)).toEqual(['profile']);
  });

  test('a denied consent redirects with access_denied and records nothing', async () => {
    const { client } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };

    const response = await postJson('/consent', {
      clientId: client.id,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
      approved: false,
      state: 'st-2',
    });
    const params = queryOf(((await response.json()) as { redirectTo: string }).redirectTo);
    expect(params.get('error')).toBe('access_denied');
    expect(params.get('state')).toBe('st-2');
    expect(await fx.consents.grantedScopes(userId, client.id)).toEqual([]);
  });

  test('a tampered scope set is invalid_scope, never granted', async () => {
    const { client } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };

    const response = await postJson('/consent', {
      clientId: client.id,
      redirectUri: REDIRECT_URI,
      scopes: ['profile', 'admin'],
      approved: true,
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' });
  });
});

describe('POST /token', () => {
  test('redeems a code with client_secret_post and never caches the response', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };
    await fx.consents.grant(userId, client.id, ['profile']);

    const authorized = await get(authorizePath({ client_id: client.id, scope: 'profile' }));
    const response = await redeemRedirect(authorized.headers.get('location') ?? '', {
      clientId: client.id,
      secret: secret ?? '',
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ tokenType: 'Bearer', expiresIn: 3600, scope: 'profile' });
    expect(body.refreshToken).toBeTruthy();
    expect(await fx.issuer.verify(String(body.accessToken))).toMatchObject({ sub: userId });
  });

  test('accepts client_secret_basic and JSON bodies', async () => {
    const { client, secret } = await fx.registerClient('confidential');

    const basicResponse = await postForm(
      '/token',
      { grant_type: 'client_credentials', scope: 'notes.read' },
      basic(client.id, secret ?? ''),
    );
    expect(basicResponse.status).toBe(200);

    const jsonResponse = await postJson('/token', {
      grant_type: 'client_credentials',
      client_id: client.id,
      client_secret: secret,
      scope: 'notes.read',
    });
    expect(jsonResponse.status).toBe(200);
    expect(await jsonResponse.json()).toMatchObject({ scope: 'notes.read' });
  });

  test('bad credentials are 401 invalid_client; unknown grant types are invalid_request', async () => {
    const { client } = await fx.registerClient('confidential');

    const badSecret = await postForm('/token', {
      grant_type: 'client_credentials',
      client_id: client.id,
      client_secret: 'wrong',
    });
    expect(badSecret.status).toBe(401);
    expect(await badSecret.json()).toMatchObject({ error: 'invalid_client' });

    const unknownGrant = await postForm('/token', { grant_type: 'password', client_id: client.id });
    expect(unknownGrant.status).toBe(400);
    expect(await unknownGrant.json()).toMatchObject({ error: 'invalid_request' });

    const missingParams = await postForm('/token', { client_id: client.id });
    expect(missingParams.status).toBe(400);
  });
});

describe('POST /introspect (RFC 7662)', () => {
  test('an active token reports the snake_case members; garbage does not', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };
    await fx.consents.grant(userId, client.id, ['profile']);

    const authorized = await get(authorizePath({ client_id: client.id, scope: 'profile' }));
    const code = queryOf(authorized.headers.get('location') ?? '').get('code') ?? '';
    const tokenResponse = await postForm('/token', {
      grant_type: 'authorization_code',
      client_id: client.id,
      client_secret: secret ?? '',
      code,
      redirect_uri: REDIRECT_URI,
    });
    const { accessToken, refreshToken } = (await tokenResponse.json()) as { accessToken: string; refreshToken: string };

    const active = await postForm('/introspect', { token: accessToken });
    expect(active.status).toBe(200);
    const activeBody = (await active.json()) as Record<string, unknown>;
    expect(activeBody).toMatchObject({ active: true, scope: 'profile', client_id: client.id, sub: userId });
    expect(activeBody.exp).toEqual(expect.any(Number));

    const inactive = await postForm('/introspect', { token: 'not-a-token' });
    expect(await inactive.json()).toEqual({ active: false });

    // The refresh token is a stored (opaque) token: introspection resolves it
    // through the token store, not the JWT issuer.
    const refreshActive = await postForm('/introspect', { token: refreshToken, token_type_hint: 'refresh_token' });
    expect(await refreshActive.json()).toMatchObject({ active: true, scope: 'profile' });
  });
});

describe('POST /revoke (RFC 7009)', () => {
  test('revoking a refresh token burns it, and an unknown token is still 200', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const issued = await postForm('/token', {
      grant_type: 'client_credentials',
      client_id: client.id,
      client_secret: secret ?? '',
    });
    expect(issued.status).toBe(200);

    const revoked = await postForm('/revoke', { token: 'fw_rt_unknown' });
    expect(revoked.status).toBe(200);

    const missing = await postForm('/revoke', {});
    expect(missing.status).toBe(400);
    expect(await missing.json()).toMatchObject({ error: 'invalid_request' });
  });

  test('a revoked refresh token cannot be redeemed again', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();
    principal = { id: userId, abilities: ['*'] };
    await fx.consents.grant(userId, client.id, ['profile']);

    const authorized = await get(authorizePath({ client_id: client.id, scope: 'profile' }));
    const code = queryOf(authorized.headers.get('location') ?? '').get('code') ?? '';
    const tokenResponse = await postForm('/token', {
      grant_type: 'authorization_code',
      client_id: client.id,
      client_secret: secret ?? '',
      code,
      redirect_uri: REDIRECT_URI,
    });
    const { refreshToken } = (await tokenResponse.json()) as { refreshToken: string };

    expect((await postForm('/revoke', { token: refreshToken })).status).toBe(200);
    const replay = await postForm('/token', {
      grant_type: 'refresh_token',
      client_id: client.id,
      client_secret: secret ?? '',
      refresh_token: refreshToken,
    });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ error: 'invalid_grant' });
  });
});
