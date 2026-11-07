import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { CONSENT_PAGE_PATH } from '../src';
import { OAuthError } from '../src/errors';
import { verifyPkceS256 } from '../src/grants';
import {
  createOAuthFixture,
  dropOAuthFixture,
  type OAuthFixture,
  principalFor,
  queryOf,
  REDIRECT_URI,
} from './support';

let fx: OAuthFixture;

/** A valid S256 challenge/verifier pair (RFC 7636 §4.2). */
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const OTHER_VERIFIER = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

beforeAll(async () => {
  fx = await createOAuthFixture();
});

afterAll(async () => {
  await dropOAuthFixture(fx);
});

/** The authorize request the fixture's public client would send, with PKCE. */
const authorizeRequest = (overrides: Partial<Parameters<OAuthFixture['server']['authorize']>[0]> = {}) => ({
  clientId: '',
  redirectUri: REDIRECT_URI,
  responseType: 'code',
  scopes: ['profile'],
  ...overrides,
});

/** Redeems a code at the token endpoint, presenting the PKCE verifier. */
const redeemWithPkce = async (input: { clientId: string; code: string; codeVerifier: string }) =>
  fx.server.token({
    grantType: 'authorization_code',
    clientId: input.clientId,
    code: input.code,
    codeVerifier: input.codeVerifier,
  });

describe('verifyPkceS256', () => {
  test('accepts only the matching verifier, in constant time', () => {
    expect(verifyPkceS256(VERIFIER, CHALLENGE)).toBe(true);
    expect(verifyPkceS256(OTHER_VERIFIER, CHALLENGE)).toBe(false);
    expect(verifyPkceS256(VERIFIER, '')).toBe(false);
    expect(verifyPkceS256('', CHALLENGE)).toBe(false);
    // Same length, different content: the timing-safe comparison decides.
    expect(verifyPkceS256(`${VERIFIER}x`, `x${CHALLENGE.slice(1)}`)).toBe(false);
  });
});

describe('authorization endpoint PKCE enforcement (RFC 7636 §4.4)', () => {
  test('a public client cannot authorize without a challenge', async () => {
    const { client } = await fx.registerClient('public');
    const userId = await fx.registerUser();

    const decision = await fx.server.authorize(authorizeRequest({ clientId: client.id }), principalFor(userId));
    const error = queryOf(decision.redirectTo);
    expect(decision.requiresConsent).toBe(false);
    expect(error.get('error')).toBe('invalid_request');
    expect(error.get('error_description')).toContain('code_challenge');
  });

  test('only the S256 method is accepted', async () => {
    const { client } = await fx.registerClient('public');
    const userId = await fx.registerUser();

    const decision = await fx.server.authorize(
      authorizeRequest({ clientId: client.id, codeChallenge: CHALLENGE, codeChallengeMethod: 'plain' }),
      principalFor(userId),
    );
    expect(queryOf(decision.redirectTo).get('error')).toBe('invalid_request');
  });

  test('a malformed challenge is rejected with a redirectable error', async () => {
    const { client } = await fx.registerClient('public');
    const userId = await fx.registerUser();

    const decision = await fx.server.authorize(
      authorizeRequest({ clientId: client.id, codeChallenge: 'too-short', codeChallengeMethod: 'S256' }),
      principalFor(userId),
    );
    expect(queryOf(decision.redirectTo).get('error')).toBe('invalid_request');
  });

  test('consent is required first, and the challenge travels to the consent screen', async () => {
    const { client } = await fx.registerClient('public');
    const userId = await fx.registerUser();

    const decision = await fx.server.authorize(
      authorizeRequest({ clientId: client.id, codeChallenge: CHALLENGE, codeChallengeMethod: 'S256' }),
      principalFor(userId),
    );
    expect(decision.requiresConsent).toBe(true);
    expect(decision.scopes).toEqual(['profile']);
    const consentUrl = new URL(decision.redirectTo);
    expect(consentUrl.pathname).toBe(CONSENT_PAGE_PATH);
    expect(consentUrl.searchParams.get('code_challenge')).toBe(CHALLENGE);
    expect(consentUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(consentUrl.searchParams.get('client_id')).toBe(client.id);
  });
});

describe('token endpoint PKCE enforcement', () => {
  test('the full public-client flow: authorize → consent → redeem with the verifier', async () => {
    const { client } = await fx.registerClient('public');
    const userId = await fx.registerUser();

    const decision = await fx.server.authorize(
      authorizeRequest({ clientId: client.id, codeChallenge: CHALLENGE, codeChallengeMethod: 'S256' }),
      principalFor(userId),
    );
    const code = await fx.server.consent(principalFor(userId), {
      clientId: client.id,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
      approved: true,
      codeChallenge: CHALLENGE,
      codeChallengeMethod: 'S256',
    });
    expect(decision.requiresConsent).toBe(true);

    const response = await redeemWithPkce({ clientId: client.id, code, codeVerifier: VERIFIER });
    expect(response.scope).toBe('profile');
    expect(response.refreshToken).toBeTruthy();
    // The JWT verifies through the framework issuer (ADR-16 reuse).
    expect(await fx.issuer.verify(response.accessToken)).toMatchObject({ sub: userId, scopes: ['profile'] });
  });

  test('a missing or wrong verifier is invalid_grant, and the code burns once', async () => {
    const { client } = await fx.registerClient('public');
    const userId = await fx.registerUser();
    const issue = async () =>
      fx.server.consent(principalFor(userId), {
        clientId: client.id,
        redirectUri: REDIRECT_URI,
        scopes: ['profile'],
        approved: true,
        codeChallenge: CHALLENGE,
        codeChallengeMethod: 'S256',
      });

    const code = await issue();
    // Wrong verifier: the code is consumed (single-use) but never redeemed.
    await expect(redeemWithPkce({ clientId: client.id, code, codeVerifier: OTHER_VERIFIER })).rejects.toMatchObject({
      oauthCode: 'invalid_grant',
    });
    // Missing verifier on an already-consumed code: still invalid_grant.
    await expect(redeemWithPkce({ clientId: client.id, code, codeVerifier: '' })).rejects.toMatchObject({
      oauthCode: 'invalid_grant',
    });

    const code2 = await issue();
    await expect(
      fx.server.token({ grantType: 'authorization_code', clientId: client.id, code: code2 }),
    ).rejects.toBeInstanceOf(OAuthError);
  });

  test('a confidential client may use PKCE, and is then bound to it', async () => {
    const { client, secret } = await fx.registerClient('confidential');
    const userId = await fx.registerUser();

    const decision = await fx.server.authorize(
      authorizeRequest({ clientId: client.id, codeChallenge: CHALLENGE, codeChallengeMethod: 'S256' }),
      principalFor(userId),
    );
    expect(decision.requiresConsent).toBe(true);
    const code = await fx.server.consent(principalFor(userId), {
      clientId: client.id,
      redirectUri: REDIRECT_URI,
      scopes: ['profile'],
      approved: true,
      codeChallenge: CHALLENGE,
      codeChallengeMethod: 'S256',
    });

    // Secret alone is not enough: the verifier is required too.
    await expect(
      fx.server.token({ grantType: 'authorization_code', clientId: client.id, clientSecret: secret, code }),
    ).rejects.toMatchObject({ oauthCode: 'invalid_grant' });
  });

  test('consent echoes the challenge for public clients and rejects one missing', async () => {
    const { client } = await fx.registerClient('public');
    const userId = await fx.registerUser();

    await expect(
      fx.server.consent(principalFor(userId), {
        clientId: client.id,
        redirectUri: REDIRECT_URI,
        scopes: ['profile'],
        approved: true,
      }),
    ).rejects.toMatchObject({ oauthCode: 'invalid_request', message: expect.stringContaining('code_challenge') });
  });
});
