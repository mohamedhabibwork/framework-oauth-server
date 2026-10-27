import { ConfigError, defineProvider, type ServiceProvider, type Token } from '@framework/core';
import { DATABASE, type DatabaseConnection } from '@framework/database';
import { PgOAuthClientStore } from './client-store';
import { PgOAuthCodeStore } from './code-store';
import { defaultOAuthServerConfig, oauthServerConfigSchema } from './config-schema';
import { PgOAuthConsentStore } from './consent-store';
import {
  AUTHORIZATION_SERVER,
  OAUTH_CLIENT_STORE,
  OAUTH_CODE_STORE,
  OAUTH_CONSENT_STORE,
  OAUTH_TOKEN_STORE,
  SCOPE_REGISTRY,
  TOKEN_ISSUER,
} from './constants';
import { defaultOAuthGrants } from './grants';
import { InMemoryScopeRegistry } from './scopes';
import { DefaultAuthorizationServer } from './server';
import { JwtTokenIssuer } from './token-issuer';
import { PgOAuthTokenStore } from './token-store';
import type { AccessClaims, GrantHandler, OAuthServerConfig, Scope, TokenIssuer } from './types';

/** Options for {@link createOAuthServerProvider}. */
export interface OAuthServerProviderOptions {
  /** Connection token the stores are built on; defaults to the shared `DATABASE`. */
  readonly connection?: Token<DatabaseConnection>;
  /** Scopes to pre-register (the framework never invents scope names). */
  readonly scopes?: readonly Scope[];
  /**
   * Pre-built token issuer — pass one built with `await JwtTokenIssuer.create({ … })`
   * to pin the signing keys (a stable JWKS across restarts, and rotation).
   * Defaults to an ephemeral JWKS-backed issuer, fine for development and tests.
   */
  readonly tokenIssuer?: TokenIssuer;
  /** Grant strategies to register; defaults to all three shipped grants. */
  readonly grants?: readonly GrantHandler[];
}

/**
 * A {@link JwtTokenIssuer} built on first use: the container constructs
 * singletons synchronously, while key generation is asynchronous. The
 * underlying issuer is memoized, so the key pair is generated exactly once.
 */
class LazyJwtTokenIssuer implements TokenIssuer {
  readonly format = 'jwt' as const;

  private issuer?: Promise<JwtTokenIssuer>;

  constructor(private readonly options: { readonly issuer: string; readonly audience: string }) {}

  private get built(): Promise<JwtTokenIssuer> {
    this.issuer ??= JwtTokenIssuer.create(this.options);
    return this.issuer;
  }

  issue(claims: AccessClaims): Promise<string> {
    return this.built.then((issuer) => issuer.issue(claims));
  }

  verify(token: string): ReturnType<TokenIssuer['verify']> {
    return this.built.then((issuer) => issuer.verify(token));
  }
}

/**
 * Registers the OAuth2 authorization-server stack from the application's
 * `oauth` config section: the four stores, the scope registry, the token
 * issuer and the {@link DefaultAuthorizationServer}. Applications add it to
 * their provider list after the database provider and compose
 * `oauth: oauthServerConfigSchema.prefault({})` into their config schema.
 *
 * The authorization server stays dark until `oauth.enabled` is true (ADR-8:
 * an attack surface is never switched on implicitly); the bindings themselves
 * are inert until resolved, so mounting `defineOAuthRoutes` is gated by the
 * application on the same flag.
 */
export function createOAuthServerProvider<TConfig extends { readonly oauth?: OAuthServerConfig }>(
  options: OAuthServerProviderOptions = {},
): ServiceProvider<TConfig> {
  return defineProvider<TConfig>({
    name: 'oauth-server',
    dependsOn: ['database'],
    register({ container, config }) {
      const parsed = oauthServerConfigSchema.safeParse(config.oauth ?? defaultOAuthServerConfig);
      if (!parsed.success) {
        throw new ConfigError(parsed.error.issues.map((issue) => `oauth.${issue.path.join('.')}: ${issue.message}`));
      }
      const settings = parsed.data;
      const connection = options.connection ?? DATABASE;

      container.singleton(OAUTH_CLIENT_STORE, (r) => new PgOAuthClientStore(r.resolve<DatabaseConnection>(connection)));
      container.singleton(
        OAUTH_CODE_STORE,
        (r) => new PgOAuthCodeStore(r.resolve<DatabaseConnection>(connection), settings.authCodeTtlSeconds),
      );
      container.singleton(OAUTH_TOKEN_STORE, (r) => new PgOAuthTokenStore(r.resolve<DatabaseConnection>(connection)));
      container.singleton(
        OAUTH_CONSENT_STORE,
        (r) => new PgOAuthConsentStore(r.resolve<DatabaseConnection>(connection)),
      );
      container.singleton(SCOPE_REGISTRY, () => new InMemoryScopeRegistry(options.scopes));
      container.singleton(
        TOKEN_ISSUER,
        () => options.tokenIssuer ?? new LazyJwtTokenIssuer({ issuer: settings.issuer, audience: settings.audience }),
      );
      container.singleton(AUTHORIZATION_SERVER, (r) => {
        const deps = {
          clients: r.resolve(OAUTH_CLIENT_STORE),
          codes: r.resolve(OAUTH_CODE_STORE),
          tokens: r.resolve(OAUTH_TOKEN_STORE),
          consents: r.resolve(OAUTH_CONSENT_STORE),
          scopes: r.resolve(SCOPE_REGISTRY),
          issuer: r.resolve(TOKEN_ISSUER),
          grants: options.grants ?? defaultOAuthGrants(),
          config: settings,
        };
        return new DefaultAuthorizationServer(deps);
      });
    },
  });
}
