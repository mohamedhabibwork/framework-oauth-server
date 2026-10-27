/** Constants of `@framework/oauth-server`: DI tokens and fixed defaults. */
import { token } from '@framework/core';
import type {
  AuthorizationServer,
  OAuthClientStore,
  OAuthCodeStore,
  OAuthConsentStore,
  OAuthTokenStore,
  ScopeRegistry,
  TokenIssuer,
} from './types';

export const OAUTH_CLIENT_STORE = token<OAuthClientStore>('oauth.client-store');
export const OAUTH_CODE_STORE = token<OAuthCodeStore>('oauth.code-store');
export const OAUTH_TOKEN_STORE = token<OAuthTokenStore>('oauth.token-store');
export const OAUTH_CONSENT_STORE = token<OAuthConsentStore>('oauth.consent-store');
export const SCOPE_REGISTRY = token<ScopeRegistry>('oauth.scope-registry');
export const TOKEN_ISSUER = token<TokenIssuer>('oauth.token-issuer');
export const AUTHORIZATION_SERVER = token<AuthorizationServer>('oauth.server');

/** Fixed defaults; the `oauth` config section overrides these. */
export const ACCESS_TOKEN_TTL_SECONDS = 3600;
export const REFRESH_TOKEN_TTL_SECONDS = 2_592_000;
export const AUTH_CODE_TTL_SECONDS = 60;
