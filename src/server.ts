import type { Principal } from '@framework/auth';
import { OAuthError, type OAuthErrorCode } from './errors';
import { introspectToken } from './token-issuer';
import type {
  AuthorizationServer,
  AuthorizationServerDeps,
  AuthorizeDecision,
  AuthorizeRequest,
  ConsentDecision,
  IntrospectionResponse,
  TokenRequest,
  TokenResponse,
} from './types';

/**
 * Path of the consent screen, relative to the issuer's base URL. The
 * authorization server never renders UI itself (API-first): a browser that
 * must approve scopes is redirected here, and the application's own consent
 * page posts the decision back to `POST /oauth/consent`.
 */
export const CONSENT_PAGE_PATH = '/oauth/consent';

/** Client redirect carrying a freshly issued authorization code (RFC 6749 §4.1.2). */
export function authorizationCodeRedirect(redirectUri: string, code: string, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  return url.toString();
}

/**
 * Client redirect carrying an RFC 6749 §4.1.2.1 error. Only ever built for a
 * redirect_uri the server has already validated against the client's
 * registration — errors must never be redirected to an unvalidated target.
 */
export function errorRedirect(redirectUri: string, code: OAuthErrorCode, description: string, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set('error', code);
  url.searchParams.set('error_description', description);
  if (state) url.searchParams.set('state', state);
  return url.toString();
}

/** Consent-screen URL carrying the pending authorization request verbatim. */
export function consentRedirect(issuer: string, request: AuthorizeRequest): string {
  const url = new URL(CONSENT_PAGE_PATH, issuer);
  url.searchParams.set('client_id', request.clientId);
  url.searchParams.set('redirect_uri', request.redirectUri);
  if (request.scopes.length > 0) url.searchParams.set('scope', request.scopes.join(' '));
  if (request.state) url.searchParams.set('state', request.state);
  if (request.codeChallenge) url.searchParams.set('code_challenge', request.codeChallenge);
  if (request.codeChallengeMethod) url.searchParams.set('code_challenge_method', request.codeChallengeMethod);
  return url.toString();
}

/**
 * The OAuth2 authorization-server orchestrator: selects the grant strategy for
 * a token request, runs the authorization/consent flows and exposes RFC 7662
 * introspection and RFC 7009 revocation.
 *
 * `authorize` embeds the RFC 6749 §4.1.2.1 redirect rules: once the client and
 * its redirect_uri are validated, every subsequent failure is answered as an
 * error redirect (`AuthorizeDecision.redirectTo`); only pre-validation
 * failures throw, because there is no safe place to send the browser.
 *
 * `consent` records the decision and issues the authorization code. A denial
 * throws `access_denied` so the route can redirect the browser home with the
 * error — the code is never issued for a request the resource owner rejected.
 */
export class DefaultAuthorizationServer implements AuthorizationServer {
  constructor(private readonly deps: AuthorizationServerDeps) {}

  async authorize(request: AuthorizeRequest, principal: Principal): Promise<AuthorizeDecision> {
    const client = await this.deps.clients.find(request.clientId);
    if (!client) throw new OAuthError('invalid_request', 'Unknown client');
    if (!client.redirectUris.includes(request.redirectUri)) {
      throw new OAuthError('invalid_request', 'redirect_uri does not match the client registration');
    }
    // The redirect target is now proven safe: further failures redirect.
    const fail = (code: OAuthErrorCode, description: string): AuthorizeDecision => ({
      redirectTo: errorRedirect(request.redirectUri, code, description, request.state),
      requiresConsent: false,
      scopes: request.scopes,
    });

    if (request.responseType !== 'code') {
      return fail('unsupported_response_type', 'Only response_type=code is supported');
    }
    if (request.codeChallengeMethod && request.codeChallengeMethod !== 'S256') {
      return fail('invalid_request', 'Only the S256 code_challenge_method is supported');
    }
    // RFC 7636 §4.2: the challenge is base64url of a 32-256 octet secret.
    if (request.codeChallenge && (request.codeChallenge.length < 43 || request.codeChallenge.length > 128)) {
      return fail('invalid_request', 'code_challenge must be 43-128 characters');
    }
    if (client.type === 'public' && !request.codeChallenge) {
      return fail('invalid_request', 'code_challenge is required for public clients');
    }

    const requested = request.scopes.length > 0 ? request.scopes : this.deps.config.defaultScopes;
    let scopes: readonly string[];
    try {
      scopes = this.resolveGrantedScopes(requested, client);
    } catch (error) {
      if (error instanceof OAuthError) return fail(error.oauthCode, error.message);
      throw error;
    }

    const granted = await this.deps.consents.grantedScopes(principal.id, client.id);
    if (scopes.some((scope) => !granted.includes(scope))) {
      return {
        redirectTo: consentRedirect(this.deps.config.issuer, { ...request, scopes }),
        requiresConsent: true,
        scopes,
      };
    }

    const code = await this.deps.codes.issue({
      clientId: client.id,
      userId: principal.id,
      redirectUri: request.redirectUri,
      scopes,
      codeChallenge: request.codeChallenge,
      codeChallengeMethod: request.codeChallengeMethod === 'S256' ? 'S256' : undefined,
    });
    return {
      redirectTo: authorizationCodeRedirect(request.redirectUri, code, request.state),
      requiresConsent: false,
      scopes,
    };
  }

  async consent(principal: Principal, decision: ConsentDecision): Promise<string> {
    const client = await this.deps.clients.find(decision.clientId);
    if (!client) throw new OAuthError('invalid_request', 'Unknown client');
    if (!client.redirectUris.includes(decision.redirectUri)) {
      throw new OAuthError('invalid_request', 'redirect_uri does not match the client registration');
    }
    if (!decision.approved) {
      throw new OAuthError('access_denied', 'The resource owner denied the request');
    }
    if (decision.codeChallengeMethod && decision.codeChallengeMethod !== 'S256') {
      throw new OAuthError('invalid_request', 'Only the S256 code_challenge_method is supported');
    }
    if (decision.codeChallenge && (decision.codeChallenge.length < 43 || decision.codeChallenge.length > 128)) {
      throw new OAuthError('invalid_request', 'code_challenge must be 43-128 characters');
    }
    if (client.type === 'public' && !decision.codeChallenge) {
      throw new OAuthError('invalid_request', 'code_challenge is required for public clients');
    }
    // The approved set is narrowed to the client's grant: a tampered consent
    // body can never widen what the client was registered to receive.
    const scopes = this.resolveGrantedScopes(decision.scopes, client);

    await this.deps.consents.grant(principal.id, client.id, scopes);
    return this.deps.codes.issue({
      clientId: client.id,
      userId: principal.id,
      redirectUri: decision.redirectUri,
      scopes,
      codeChallenge: decision.codeChallenge,
      codeChallengeMethod: decision.codeChallenge ? 'S256' : undefined,
    });
  }

  async token(request: TokenRequest): Promise<TokenResponse> {
    const grant = this.deps.grants.find((candidate) => candidate.type === request.grantType);
    if (!grant) {
      throw new OAuthError('unsupported_grant_type', `The ${request.grantType} grant is not supported`);
    }
    return grant.handle(request, this.deps);
  }

  async introspect(token: string): Promise<IntrospectionResponse> {
    const verified = await introspectToken(token, this.deps.issuer);
    if (verified.active) return verified;
    // The issuer verifies JWTs (and its own opaque access tokens); anything
    // else may be a stored refresh/access token — resolve it via the store.
    const record = (await this.deps.tokens.findAccess(token)) ?? (await this.deps.tokens.findRefresh(token));
    if (!record || record.revokedAt || record.expiresAt.getTime() <= Date.now()) return { active: false };
    return {
      active: true,
      scope: record.scopes.join(' '),
      clientId: record.clientId,
      ...(record.userId !== null ? { sub: record.userId } : {}),
      exp: Math.floor(record.expiresAt.getTime() / 1000),
    };
  }

  async revoke(token: string): Promise<void> {
    // JWT access tokens are stateless and expire on their own; revocation here
    // covers the stored refresh tokens (and opaque tokens when that issuer is used).
    await this.deps.tokens.revoke(token);
  }

  /** Validates requested scopes against the registry, then narrows to the client's grant. */
  private resolveGrantedScopes(requested: readonly string[], client: { allowedScopes: readonly string[] }) {
    const unknown = requested.filter((name) => this.deps.scopes.validate([name]).length > 0);
    if (unknown.length > 0) {
      throw new OAuthError('invalid_scope', `Unknown scope: ${unknown.join(', ')}`);
    }
    const granted = requested.filter((name) => client.allowedScopes.includes(name));
    if (granted.length === 0) {
      throw new OAuthError('invalid_scope', 'None of the requested scopes are allowed for this client');
    }
    return granted;
  }
}
