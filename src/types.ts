/**
 * Every interface and type of `@framework/oauth-server` (the Passport equivalent).
 * Type-only: importing from this module never emits runtime code.
 *
 * Two reuse points keep this package small and correct:
 *  (a) access tokens are **JWT-format**, signed with the framework JWKS via
 *      `jose`, so the existing `@framework/auth` `jwt` guard verifies them
 *      unchanged (or opaque tokens resolved via RFC 7662 introspection);
 *  (b) identity is **reused, never duplicated** — OAuth `userId`s are FKs to
 *      the framework-owned `users` table and the consent screen authenticates
 *      through the existing session guard.
 */
import type { Principal } from '@framework/auth';

export type OAuthGrantType = 'authorization_code' | 'client_credentials' | 'refresh_token';
export type OAuthClientType = 'confidential' | 'public';

export interface OAuthClient {
  readonly id: string;
  readonly name: string;
  readonly type: OAuthClientType;
  readonly redirectUris: readonly string[];
  readonly allowedGrants: readonly OAuthGrantType[];
  readonly allowedScopes: readonly string[];
  /** Hashed at rest; absent for public clients (which must use PKCE). */
  readonly secretHash?: string;
}

export interface RegisterClientInput {
  readonly name: string;
  readonly type: OAuthClientType;
  readonly redirectUris: readonly string[];
  readonly allowedGrants: readonly OAuthGrantType[];
  readonly allowedScopes: readonly string[];
}

export interface OAuthClientStore {
  find(id: string): Promise<OAuthClient | null>;
  /** Constant-time secret verification; false for public clients. */
  verifySecret(id: string, secret: string): Promise<boolean>;
  register(input: RegisterClientInput): Promise<{ readonly client: OAuthClient; readonly secret?: string }>;
  list(): Promise<readonly OAuthClient[]>;
}

export interface IssueCodeInput {
  readonly clientId: string;
  readonly userId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  /** PKCE challenge (required for public clients). */
  readonly codeChallenge?: string;
  readonly codeChallengeMethod?: 'S256';
}

export interface OAuthCodeRecord {
  readonly clientId: string;
  readonly userId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly codeChallenge: string | null;
  readonly codeChallengeMethod: string | null;
}

export interface OAuthCodeStore {
  /** Issues a single-use authorization code (plaintext). */
  issue(input: IssueCodeInput): Promise<string>;
  /** Consumes a code atomically; PKCE is verified by the caller. */
  consume(code: string, clientId: string): Promise<OAuthCodeRecord | null>;
}

export interface IssueAccessInput {
  readonly clientId: string;
  readonly userId: string | null;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
}

export interface IssuedAccessToken {
  readonly token: string;
  readonly expiresAt: Date;
  readonly scopes: readonly string[];
}

export interface IssueRefreshInput {
  readonly clientId: string;
  readonly userId: string | null;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
}

export interface OAuthAccessRecord {
  readonly tokenHash: string;
  readonly clientId: string;
  readonly userId: string | null;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
}

export interface OAuthRefreshRecord {
  readonly tokenHash: string;
  readonly clientId: string;
  readonly userId: string | null;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
}

export interface OAuthTokenStore {
  issueAccess(input: IssueAccessInput): Promise<IssuedAccessToken>;
  issueRefresh(input: IssueRefreshInput): Promise<string>;
  findAccess(token: string): Promise<OAuthAccessRecord | null>;
  findRefresh(token: string): Promise<OAuthRefreshRecord | null>;
  revoke(token: string): Promise<boolean>;
  revokeAllForUser(userId: string): Promise<number>;
  prune(now?: Date): Promise<number>;
}

export interface OAuthConsentStore {
  grantedScopes(userId: string, clientId: string): Promise<readonly string[]>;
  grant(userId: string, clientId: string, scopes: readonly string[]): Promise<void>;
  revoke(userId: string, clientId: string): Promise<void>;
}

export interface Scope {
  readonly name: string;
  readonly description: string;
  /** Scopes implied by this one (transitively). */
  readonly implies?: readonly string[];
}

export interface ScopeRegistry {
  register(scope: Scope): void;
  all(): readonly Scope[];
  /** Returns the unknown names (empty when every name is registered). */
  validate(names: readonly string[]): string[];
}

/** Claims carried by an issued access token. */
export interface AccessClaims {
  /** Subject: the local user id, or `null` for client-credentials tokens. */
  readonly sub: string | null;
  readonly clientId: string;
  readonly scopes: readonly string[];
  /** Expiry as a Unix timestamp (seconds). */
  readonly expiresAt: number;
  readonly issuer: string;
  readonly audience: string;
}

/**
 * Token format strategy. `JwtTokenIssuer` signs with the framework JWKS so the
 * existing `jwt` guard verifies it; `OpaqueTokenIssuer` stores a hashed value.
 */
export interface TokenIssuer {
  readonly format: 'jwt' | 'opaque';
  issue(claims: AccessClaims): Promise<string>;
  verify(token: string): Promise<AccessClaims | null>;
}

export interface TokenRequest {
  readonly grantType: OAuthGrantType;
  readonly clientId: string;
  readonly clientSecret?: string;
  readonly code?: string;
  readonly codeVerifier?: string;
  readonly redirectUri?: string;
  readonly refreshToken?: string;
  readonly scopes?: readonly string[];
}

export interface TokenResponse {
  readonly accessToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresIn: number;
  readonly refreshToken?: string;
  /** Space-delimited granted scopes (RFC 6749 §5.1). */
  readonly scope: string;
}

/** Collaborators a `GrantHandler` needs to complete a token request. */
export interface GrantDeps {
  readonly clients: OAuthClientStore;
  readonly codes: OAuthCodeStore;
  readonly tokens: OAuthTokenStore;
  readonly consents: OAuthConsentStore;
  readonly scopes: ScopeRegistry;
  readonly issuer: TokenIssuer;
  /** Validated `oauth` config: issuer/audience and the token lifetimes. */
  readonly config: OAuthServerConfig;
}

/** One grant type: client auth + request validation + token issuance. */
export interface GrantHandler {
  readonly type: OAuthGrantType;
  handle(request: TokenRequest, deps: GrantDeps): Promise<TokenResponse>;
}

export interface AuthorizeRequest {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly responseType: string;
  readonly scopes: readonly string[];
  readonly state?: string;
  readonly codeChallenge?: string;
  readonly codeChallengeMethod?: string;
}

export interface AuthorizeDecision {
  /** Where the browser should be sent (consent screen, or redirect with code/error). */
  readonly redirectTo: string;
  readonly requiresConsent: boolean;
  readonly scopes: readonly string[];
}

export interface ConsentDecision {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly approved: boolean;
  readonly state?: string;
  /**
   * PKCE challenge from the original authorization request, echoed back by the
   * consent screen so the issued code stays bound to the verifier (RFC 7636).
   * Required for public clients; optional for confidential ones.
   */
  readonly codeChallenge?: string;
  readonly codeChallengeMethod?: 'S256';
}

/** RFC 7662 token introspection response. */
export interface IntrospectionResponse {
  readonly active: boolean;
  readonly scope?: string;
  readonly clientId?: string;
  readonly sub?: string;
  /** Expiry as a Unix timestamp (seconds). */
  readonly exp?: number;
}

/** Collaborators for the `AuthorizationServer` orchestrator. */
export interface AuthorizationServerDeps {
  readonly clients: OAuthClientStore;
  readonly codes: OAuthCodeStore;
  readonly tokens: OAuthTokenStore;
  readonly consents: OAuthConsentStore;
  readonly scopes: ScopeRegistry;
  readonly issuer: TokenIssuer;
  readonly grants: readonly GrantHandler[];
  /** Validated `oauth` config: issuer/audience and the token lifetimes. */
  readonly config: OAuthServerConfig;
}

/** The OAuth2 authorization server orchestrator. */
export interface AuthorizationServer {
  /** Consent or redirect for an authorization request; requires an authenticated principal. */
  authorize(request: AuthorizeRequest, principal: Principal): Promise<AuthorizeDecision>;
  /** Records consent and issues an authorization code. */
  consent(principal: Principal, decision: ConsentDecision): Promise<string>;
  token(request: TokenRequest): Promise<TokenResponse>;
  introspect(token: string): Promise<IntrospectionResponse>;
  revoke(token: string): Promise<void>;
}

/** Collaborators for the OAuth HTTP routes. */
export interface OAuthRoutesDeps {
  readonly server: AuthorizationServer;
  readonly config: OAuthServerConfig;
  readonly scopes: ScopeRegistry;
  /** Registered grants, published verbatim in the metadata document. */
  readonly grants: readonly GrantHandler[];
}

/** Validated `oauth` config section. */
export interface OAuthServerConfig {
  readonly enabled: boolean;
  readonly issuer: string;
  readonly audience: string;
  readonly accessTokenTtlSeconds: number;
  readonly refreshTokenTtlSeconds: number;
  readonly authCodeTtlSeconds: number;
  readonly defaultScopes: readonly string[];
}
