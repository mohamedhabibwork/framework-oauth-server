import type { Principal } from '@framework/auth';
import { currentPrincipal, type FrameworkEnv, unauthenticated } from '@framework/http';
import type { Context } from 'hono';
import { Hono } from 'hono';
import { z } from 'zod/v4';
import { OAuthError } from './errors';
import { authorizationCodeRedirect, errorRedirect } from './server';
import type { IntrospectionResponse, OAuthRoutesDeps, TokenRequest } from './types';

/**
 * Mount prefix the routes assume. Applications mount them with
 * `app.route(OAUTH_ROUTES_PREFIX, defineOAuthRoutes(deps))` and point
 * `oauth.issuer` at the public base URL, so the metadata document and consent
 * redirect resolve to the same paths the app serves.
 */
export const OAUTH_ROUTES_PREFIX = '/oauth';

/** RFC 6749 §5.1 / RFC 7662 §2.2: token responses are never cached. */
const NO_STORE_HEADERS = { 'cache-control': 'no-store', pragma: 'no-cache' } as const;

/** RFC 6749 §3.2 parameters (form-encoded per spec; JSON accepted for machine clients). */
const tokenBodySchema = z.object({
  grant_type: z.enum(['authorization_code', 'client_credentials', 'refresh_token']),
  client_id: z.string().min(1).max(200).optional(),
  client_secret: z.string().min(1).max(400).optional(),
  code: z.string().min(1).max(400).optional(),
  code_verifier: z.string().min(1).max(128).optional(),
  redirect_uri: z.string().min(1).max(2000).optional(),
  refresh_token: z.string().min(1).max(400).optional(),
  scope: z.string().max(2000).optional(),
});

/** RFC 6749 §4.1.2.1 query parameters. */
const authorizeQuerySchema = z.object({
  client_id: z.string().min(1).max(200),
  redirect_uri: z.string().min(1).max(2000),
  response_type: z.string().min(1).max(40),
  scope: z.string().max(2000).optional(),
  state: z.string().max(2000).optional(),
  code_challenge: z.string().min(1).max(128).optional(),
  code_challenge_method: z.string().max(10).optional(),
});

/** Consent screen's decision post (the pending request, plus the verdict). */
const consentBodySchema = z.object({
  clientId: z.string().min(1).max(200),
  redirectUri: z.string().min(1).max(2000),
  scopes: z.array(z.string().min(1).max(100)).max(100).default([]),
  approved: z.boolean(),
  state: z.string().max(2000).optional(),
  codeChallenge: z.string().min(1).max(128).optional(),
  codeChallengeMethod: z.literal('S256').optional(),
});

/** RFC 7662 §2.1 introspection request. */
const introspectBodySchema = z.object({
  token: z.string().min(1).max(2000),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
});

/** RFC 7009 §2.1 revocation request. */
const revokeBodySchema = z.object({
  token: z.string().min(1).max(2000),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
});

type TokenBody = z.infer<typeof tokenBodySchema>;

/** Flattens a JSON body (or repeated form values) to single string entries. */
function toStringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (value === null || typeof value !== 'object') return out;
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (typeof raw === 'string') out[key] = raw;
    else if (Array.isArray(raw)) out[key] = raw.filter((entry) => typeof entry === 'string').join(' ');
  }
  return out;
}

/**
 * Reads request parameters as a flat string map: form-encoded bodies (the RFC
 * 6749 norm) and JSON bodies (machine clients) are both accepted. Repeated
 * form values are space-joined, matching how `scope` is transmitted.
 */
async function readParams(c: Context<FrameworkEnv>): Promise<Record<string, string>> {
  if ((c.req.header('content-type') ?? '').includes('json')) {
    return toStringMap(await c.req.json().catch(() => null));
  }
  return toStringMap(await c.req.parseBody());
}

/** RFC 6749 §2.3.1 HTTP Basic client credentials, when the header is present. */
function basicClientCredentials(c: Context<FrameworkEnv>): { clientId: string; clientSecret?: string } | null {
  const header = c.req.header('authorization');
  if (!header?.startsWith('Basic ')) return null;
  let decoded: string;
  try {
    decoded = atob(header.slice('Basic '.length).trim());
  } catch {
    return null;
  }
  const separator = decoded.indexOf(':');
  if (separator < 0) return null;
  return {
    clientId: decodeURIComponent(decoded.slice(0, separator).replaceAll('+', ' ')),
    clientSecret: decodeURIComponent(decoded.slice(separator + 1).replaceAll('+', ' ')),
  };
}

/** RFC 6749 §5.2 error body, verbatim. Non-OAuth failures reach the framework error boundary. */
function oauthErrorResponse(c: Context<FrameworkEnv>, error: unknown): Response {
  if (error instanceof OAuthError) {
    return c.json({ error: error.oauthCode, error_description: error.message }, error.status);
  }
  throw error;
}

/** Malformed parameters map to the RFC `invalid_request` body (400). */
function invalidRequest(c: Context<FrameworkEnv>, description: string): Response {
  return c.json({ error: 'invalid_request', error_description: description }, 400);
}

/** The authenticated principal, or a 401. OAuth routes mount behind the auth actor resolver. */
function requirePrincipal(c: Context<FrameworkEnv>): Principal {
  const principal = currentPrincipal(c);
  if (!principal) throw unauthenticated();
  // The auth actor resolver installs the full Principal (session/api-token/jwt).
  return principal as Principal;
}

/** Maps the verified claims to the RFC 7662 response members (snake_case). */
function introspectionBody(response: IntrospectionResponse): Record<string, unknown> {
  if (!response.active) return { active: false };
  return {
    active: true,
    ...(response.scope !== undefined ? { scope: response.scope } : {}),
    ...(response.clientId !== undefined ? { client_id: response.clientId } : {}),
    ...(response.sub !== undefined ? { sub: response.sub } : {}),
    ...(response.exp !== undefined ? { exp: response.exp } : {}),
  };
}

/**
 * OAuth2 endpoints: the authorization-code/consent browser flow, the token
 * endpoint (RFC 6749 §3.2), RFC 7662 introspection and RFC 7009 revocation,
 * plus the RFC 8414 authorization-server metadata document.
 *
 * `GET /authorize` redirects to whatever `AuthorizationServer.authorize`
 * decides — the client's redirect_uri (with a code or an error) or the
 * consent screen. `POST /consent` answers with `{ redirectTo }` for the SPA
 * consent screen to navigate to, so the browser never posts a cross-origin
 * form. `POST /introspect` and `POST /revoke` are meant to be called by
 * confidential clients: applications should mount them behind their own
 * authentication middleware (the routes carry no client store).
 */
export function defineOAuthRoutes(deps: OAuthRoutesDeps): Hono<FrameworkEnv> {
  const server = deps.server;
  const base = deps.config.issuer;

  return (
    new Hono<FrameworkEnv>()
      // -- RFC 8414 authorization-server metadata -------------------------------
      .get('/.well-known/oauth-authorization-server', (c) =>
        c.json({
          issuer: base,
          authorization_endpoint: `${base}${OAUTH_ROUTES_PREFIX}/authorize`,
          token_endpoint: `${base}${OAUTH_ROUTES_PREFIX}/token`,
          introspection_endpoint: `${base}${OAUTH_ROUTES_PREFIX}/introspect`,
          revocation_endpoint: `${base}${OAUTH_ROUTES_PREFIX}/revoke`,
          response_types_supported: ['code'],
          grant_types_supported: deps.grants.map((grant) => grant.type),
          scopes_supported: deps.scopes.all().map((scope) => scope.name),
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        }),
      )
      // -- Authorization + consent (browser flow) ---------------------------------
      .get('/authorize', async (c) => {
        const principal = requirePrincipal(c);
        const parsed = authorizeQuerySchema.safeParse(
          Object.fromEntries(Object.entries(c.req.query()).map(([key, value]) => [key, value ?? ''])),
        );
        if (!parsed.success) {
          return invalidRequest(c, parsed.error.issues.map((issue) => issue.message).join('; '));
        }
        const query = parsed.data;
        const scopes = query.scope ? query.scope.split(' ').filter(Boolean) : [];
        try {
          const decision = await server.authorize(
            {
              clientId: query.client_id,
              redirectUri: query.redirect_uri,
              responseType: query.response_type,
              scopes,
              state: query.state,
              codeChallenge: query.code_challenge,
              codeChallengeMethod: query.code_challenge_method === 'S256' ? 'S256' : undefined,
            },
            principal,
          );
          return c.redirect(decision.redirectTo);
        } catch (error) {
          return oauthErrorResponse(c, error);
        }
      })
      .post('/consent', async (c) => {
        const principal = requirePrincipal(c);
        const body = await c.req.json().catch(() => null);
        const parsed = consentBodySchema.safeParse(body);
        if (!parsed.success) {
          return invalidRequest(c, parsed.error.issues.map((issue) => issue.message).join('; '));
        }
        const decision = parsed.data;
        const state = decision.state;
        try {
          if (!decision.approved) {
            // RFC 6749 §4.1.2.1: a denial is a redirect with access_denied.
            return c.json({
              redirectTo: errorRedirect(
                decision.redirectUri,
                'access_denied',
                'The resource owner denied the request',
                state,
              ),
            });
          }
          const code = await server.consent(principal, {
            clientId: decision.clientId,
            redirectUri: decision.redirectUri,
            scopes: decision.scopes,
            approved: true,
            state,
            codeChallenge: decision.codeChallenge,
            codeChallengeMethod: decision.codeChallengeMethod,
          });
          return c.json({ redirectTo: authorizationCodeRedirect(decision.redirectUri, code, state) });
        } catch (error) {
          return oauthErrorResponse(c, error);
        }
      })
      // -- Token endpoint (RFC 6749 §3.2) -----------------------------------------
      .post('/token', async (c) => {
        const basic = basicClientCredentials(c);
        const parsed = tokenBodySchema.safeParse(await readParams(c));
        if (!parsed.success) {
          return invalidRequest(c, parsed.error.issues.map((issue) => issue.message).join('; '));
        }
        const body: TokenBody = parsed.data;
        const request: TokenRequest = {
          grantType: body.grant_type,
          clientId: basic?.clientId ?? body.client_id ?? '',
          clientSecret: basic?.clientSecret ?? body.client_secret,
          code: body.code,
          codeVerifier: body.code_verifier,
          redirectUri: body.redirect_uri,
          refreshToken: body.refresh_token,
          scopes: body.scope ? body.scope.split(' ').filter(Boolean) : undefined,
        };
        try {
          return c.json(await server.token(request), 200, NO_STORE_HEADERS);
        } catch (error) {
          return oauthErrorResponse(c, error);
        }
      })
      // -- Introspection (RFC 7662) ----------------------------------------------
      .post('/introspect', async (c) => {
        const parsed = introspectBodySchema.safeParse(await readParams(c));
        if (!parsed.success) {
          return invalidRequest(c, parsed.error.issues.map((issue) => issue.message).join('; '));
        }
        try {
          const response = await server.introspect(parsed.data.token);
          return c.json(introspectionBody(response), 200, NO_STORE_HEADERS);
        } catch (error) {
          return oauthErrorResponse(c, error);
        }
      })
      // -- Revocation (RFC 7009) -------------------------------------------------
      .post('/revoke', async (c) => {
        const parsed = revokeBodySchema.safeParse(await readParams(c));
        if (!parsed.success) {
          return invalidRequest(c, parsed.error.issues.map((issue) => issue.message).join('; '));
        }
        try {
          await server.revoke(parsed.data.token);
          // RFC 7009 §2.2: an invalid token is not an error — the reply is 200 either way.
          return c.body(null, 200);
        } catch (error) {
          return oauthErrorResponse(c, error);
        }
      })
  );
}
