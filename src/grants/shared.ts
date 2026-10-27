import { createHash, timingSafeEqual } from 'node:crypto';
import { OAuthError } from '../errors';
import type { GrantDeps, OAuthClient, OAuthClientStore, OAuthGrantType, TokenRequest, TokenResponse } from '../types';

/** Constant-time PKCE S256 check (`base64url(sha256(verifier)) === challenge`). */
export function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
  if (!codeVerifier || !codeChallenge) return false;
  const computed = Buffer.from(createHash('sha256').update(codeVerifier).digest('base64url'), 'utf8');
  const expected = Buffer.from(codeChallenge, 'utf8');
  if (computed.length !== expected.length) return false;
  return timingSafeEqual(computed, expected);
}

/**
 * Resolves the scopes a request actually gets: the requested set when one is
 * sent, otherwise what the client is allowed. Every name must be registered
 * and inside the client's `allowedScopes`; anything else is `invalid_scope`.
 * Never widens beyond the client's grant.
 */
export function resolveGrantedScopes(
  requested: readonly string[] | undefined,
  client: OAuthClient,
  isRegistered: (name: string) => boolean,
): readonly string[] {
  const names = requested && requested.length > 0 ? requested : client.allowedScopes;
  if (names.some((name) => !isRegistered(name))) {
    throw new OAuthError('invalid_scope', 'One or more requested scopes are unknown');
  }
  const granted = names.filter((name) => client.allowedScopes.includes(name));
  if (granted.length === 0) {
    throw new OAuthError('invalid_scope', 'None of the requested scopes are allowed for this client');
  }
  return granted;
}

/**
 * Client authentication per RFC 6749 §2.3.1. Confidential clients must present
 * the secret (verified in constant time by the store); public clients have no
 * secret and rely on PKCE instead — a secret supplied for them is ignored.
 */
export async function authenticateClient(request: TokenRequest, clients: OAuthClientStore): Promise<OAuthClient> {
  if (!request.clientId) {
    throw new OAuthError('invalid_request', 'client_id is required');
  }
  const client = await clients.find(request.clientId);
  if (!client) {
    throw new OAuthError('invalid_client', 'Unknown client');
  }
  if (client.type !== 'confidential') return client;

  if (!request.clientSecret) {
    throw new OAuthError('invalid_client', 'client_secret is required for a confidential client');
  }
  if (!(await clients.verifySecret(client.id, request.clientSecret))) {
    throw new OAuthError('invalid_client', 'Client authentication failed');
  }
  return client;
}

/**
 * RFC 6749 §7.5.1: the authenticated client must have been registered for the
 * grant it is attempting. Checked after client authentication so an impostor
 * cannot probe which grants a client holds.
 */
export function assertGrantAllowed(client: OAuthClient, grantType: OAuthGrantType): void {
  if (!client.allowedGrants.includes(grantType)) {
    throw new OAuthError('unauthorized_client', `The client may not use the ${grantType} grant`);
  }
}

/**
 * Narrows a requested scope set to what was already granted (RFC 6749 §3.3 /
 * §6): an omitted request keeps the granted set unchanged, and a request that
 * names a scope outside the granted set is `invalid_scope` — silently
 * dropping scopes would hide client bugs.
 */
export function narrowScopes(requested: readonly string[] | undefined, granted: readonly string[]): readonly string[] {
  if (!requested || requested.length === 0) return granted;
  if (requested.some((scope) => !granted.includes(scope))) {
    throw new OAuthError('invalid_scope', 'The requested scope exceeds the granted scope');
  }
  return granted.filter((scope) => requested.includes(scope));
}

/**
 * Issues the access token through the configured issuer (JWT or opaque) and,
 * when asked, a rotating refresh token from the token store. One place so all
 * grants answer with identical TTLs and the RFC 6749 §5.1 response shape.
 */
export async function issueTokenPair(
  deps: GrantDeps,
  input: {
    readonly clientId: string;
    /** `null` for client-credentials tokens (there is no end user). */
    readonly userId: string | null;
    readonly scopes: readonly string[];
    readonly withRefresh: boolean;
  },
): Promise<TokenResponse> {
  const expiresAt = Math.floor(Date.now() / 1000) + deps.config.accessTokenTtlSeconds;
  const accessToken = await deps.issuer.issue({
    sub: input.userId,
    clientId: input.clientId,
    scopes: input.scopes,
    expiresAt,
    issuer: deps.config.issuer,
    audience: deps.config.audience,
  });
  const refreshToken = input.withRefresh
    ? await deps.tokens.issueRefresh({
        clientId: input.clientId,
        userId: input.userId,
        scopes: input.scopes,
        expiresAt: new Date(Date.now() + deps.config.refreshTokenTtlSeconds * 1000),
      })
    : undefined;
  return {
    accessToken,
    tokenType: 'Bearer',
    expiresIn: deps.config.accessTokenTtlSeconds,
    ...(refreshToken ? { refreshToken } : {}),
    scope: input.scopes.join(' '),
  };
}
