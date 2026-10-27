// Public API of @framework/oauth-server.
// Convention: every interface/type lives in `./types`, every constant in
// `./constants`; runtime values (stores, grants, server, routes, provider) stay in their modules.
export { generateClientId, generateClientSecret, hashClientSecret, PgOAuthClientStore } from './client-store';
export { generateAuthCode, hashAuthCode, PgOAuthCodeStore } from './code-store';
export { defaultOAuthServerConfig, oauthServerConfigSchema } from './config-schema';
export { PgOAuthConsentStore } from './consent-store';
export {
  ACCESS_TOKEN_TTL_SECONDS,
  AUTH_CODE_TTL_SECONDS,
  AUTHORIZATION_SERVER,
  OAUTH_CLIENT_STORE,
  OAUTH_CODE_STORE,
  OAUTH_CONSENT_STORE,
  OAUTH_TOKEN_STORE,
  REFRESH_TOKEN_TTL_SECONDS,
  SCOPE_REGISTRY,
  TOKEN_ISSUER,
} from './constants';
export {
  AuthorizationCodeGrant,
  assertGrantAllowed,
  authenticateClient,
  ClientCredentialsGrant,
  defaultOAuthGrants,
  issueTokenPair,
  narrowScopes,
  RefreshTokenGrant,
  resolveGrantedScopes,
  verifyPkceS256,
} from './grants';
export { createOAuthServerProvider, type OAuthServerProviderOptions } from './provider';
export { defineOAuthRoutes, OAUTH_ROUTES_PREFIX } from './routes';
export type {
  OAuthAccessTokenRow,
  OAuthAuthCodeRow,
  OAuthClientRow,
  OAuthConsentRow,
  OAuthRefreshTokenRow,
} from './schema/tables';
export {
  oauthAccessTokens,
  oauthAuthCodes,
  oauthClients,
  oauthConsents,
  oauthRefreshTokens,
} from './schema/tables';
export { expandScopes, InMemoryScopeRegistry } from './scopes';
export {
  authorizationCodeRedirect,
  CONSENT_PAGE_PATH,
  consentRedirect,
  DefaultAuthorizationServer,
  errorRedirect,
} from './server';
export type { JwtSigningAlgorithm, JwtTokenIssuerOptions, OpaqueTokenIssuerOptions } from './token-issuer';
export {
  introspectToken,
  JwtTokenIssuer,
  OpaqueTokenIssuer,
} from './token-issuer';
export { generateOAuthToken, hashOAuthToken, PgOAuthTokenStore } from './token-store';
export type {
  AccessClaims,
  AuthorizationServer,
  AuthorizationServerDeps,
  AuthorizeDecision,
  AuthorizeRequest,
  ConsentDecision,
  GrantDeps,
  GrantHandler,
  IntrospectionResponse,
  IssueAccessInput,
  IssueCodeInput,
  IssuedAccessToken,
  IssueRefreshInput,
  OAuthAccessRecord,
  OAuthClient,
  OAuthClientStore,
  OAuthClientType,
  OAuthCodeRecord,
  OAuthCodeStore,
  OAuthConsentStore,
  OAuthGrantType,
  OAuthRefreshRecord,
  OAuthServerConfig,
  OAuthTokenStore,
  RegisterClientInput,
  Scope,
  ScopeRegistry,
  TokenIssuer,
  TokenRequest,
  TokenResponse,
} from './types';
