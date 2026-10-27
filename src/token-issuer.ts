import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JSONWebKeySet,
  type JWSAlgorithm,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from 'jose';
import type { AccessClaims, IntrospectionResponse, OAuthTokenStore, TokenIssuer } from './types';

/** Asymmetric algorithms the framework's `jwt` guard accepts (never `none`/HS*). */
export type JwtSigningAlgorithm = Extract<JWSAlgorithm, 'RS256' | 'ES256' | 'PS256' | 'EdDSA'>;

export interface JwtTokenIssuerOptions {
  /** Expected `iss`; resource servers set `auth.jwt.issuer` to the same value. */
  readonly issuer: string;
  /** Expected `aud`; resource servers set `auth.jwt.audience` to the same value. */
  readonly audience: string;
  /** Signing algorithm. Defaults to RS256. */
  readonly algorithm?: JwtSigningAlgorithm;
  /** `kid` advertised in the JWKS and set on the token header. Defaults to `oauth-1`. */
  readonly kid?: string;
  /** Signing key pair. Omit to generate an ephemeral RS256 pair (dev/tests). */
  readonly keys?: CryptoKeyPair;
}

const scopesFrom = (value: unknown): readonly string[] =>
  typeof value === 'string' ? value.split(' ').filter(Boolean) : [];

/** Maps a verified JWT payload back to the framework's access-token claims. */
function claimsFromPayload(payload: JWTPayload, issuer: string, audience: string): AccessClaims | null {
  const clientId = typeof payload.client_id === 'string' ? payload.client_id : '';
  if (!clientId) return null;
  const sub = typeof payload.sub === 'string' && payload.sub ? payload.sub : null;
  const expiresAt = typeof payload.exp === 'number' ? payload.exp : 0;
  return { sub, clientId, scopes: scopesFrom(payload.scope), expiresAt, issuer, audience };
}

/**
 * JWT access-token issuer. Signs with an asymmetric key pair via `jose` (the
 * same library the `@framework/auth` `jwt` guard verifies with) and publishes
 * the matching public JWKS, so a token minted here is accepted by any resource
 * server whose `auth.jwt` points at this issuer — no new verification code
 * (ADR-16). The space-delimited `scope` claim becomes principal abilities.
 *
 * The issuer's configured `issuer`/`audience` are authoritative: they are
 * written on every token and expected on every verification, so the issuer can
 * never mint a token it would itself reject. (Any `issuer`/`audience` carried
 * on the incoming claims are ignored for signing; they are returned by
 * `verify` for symmetry with the opaque issuer.)
 */
export class JwtTokenIssuer implements TokenIssuer {
  readonly format = 'jwt' as const;
  private readonly algorithm: JwtSigningAlgorithm;
  private readonly kid: string;
  private readonly keys: CryptoKeyPair;
  private jwksPromise?: Promise<JSONWebKeySet>;
  private keyStorePromise?: Promise<ReturnType<typeof createLocalJWKSet>>;

  private constructor(
    private readonly options: JwtTokenIssuerOptions,
    keys: CryptoKeyPair,
  ) {
    this.algorithm = options.algorithm ?? 'RS256';
    this.kid = options.kid ?? 'oauth-1';
    this.keys = keys;
  }

  /** Builds an issuer, generating an ephemeral key pair when none is supplied. */
  static async create(options: JwtTokenIssuerOptions): Promise<JwtTokenIssuer> {
    const keys = options.keys ?? (await generateKeyPair(options.algorithm ?? 'RS256', { extractable: true }));
    return new JwtTokenIssuer(options, keys);
  }

  /** Public key set for a resource server's `jwt` guard (`auth.jwt.jwks`). */
  jwks(): Promise<JSONWebKeySet> {
    this.jwksPromise ??= this.buildJwks();
    return this.jwksPromise;
  }

  private async buildJwks(): Promise<JSONWebKeySet> {
    const publicKey = await exportJWK(this.keys.publicKey);
    return { keys: [{ ...publicKey, kid: this.kid, alg: this.algorithm, use: 'sig' }] };
  }

  private keyStore(): Promise<ReturnType<typeof createLocalJWKSet>> {
    this.keyStorePromise ??= this.jwks().then((set) => createLocalJWKSet(set));
    return this.keyStorePromise;
  }

  async issue(claims: AccessClaims): Promise<string> {
    const payload: Record<string, unknown> = { client_id: claims.clientId, scope: claims.scopes.join(' ') };
    if (claims.sub !== null) payload.sub = claims.sub;
    return new SignJWT(payload)
      .setProtectedHeader({ alg: this.algorithm, kid: this.kid })
      .setIssuedAt()
      .setIssuer(this.options.issuer)
      .setAudience(this.options.audience)
      .setExpirationTime(claims.expiresAt)
      .sign(this.keys.privateKey);
  }

  async verify(token: string): Promise<AccessClaims | null> {
    try {
      const { payload } = await jwtVerify(token, await this.keyStore(), {
        algorithms: [this.algorithm],
        issuer: this.options.issuer,
        audience: this.options.audience,
      });
      return claimsFromPayload(payload, this.options.issuer, this.options.audience);
    } catch {
      return null;
    }
  }
}

export interface OpaqueTokenIssuerOptions {
  readonly tokens: OAuthTokenStore;
  readonly issuer: string;
  readonly audience: string;
}

/**
 * Opaque access-token issuer: stores a hashed value in the token store and
 * resolves it on verification, so revocation is immediate. Resource servers
 * resolve these through RFC 7662 introspection rather than a JWKS.
 */
export class OpaqueTokenIssuer implements TokenIssuer {
  readonly format = 'opaque' as const;

  constructor(private readonly options: OpaqueTokenIssuerOptions) {}

  async issue(claims: AccessClaims): Promise<string> {
    const issued = await this.options.tokens.issueAccess({
      clientId: claims.clientId,
      userId: claims.sub,
      scopes: claims.scopes,
      expiresAt: new Date(claims.expiresAt * 1000),
    });
    return issued.token;
  }

  async verify(token: string): Promise<AccessClaims | null> {
    const record = await this.options.tokens.findAccess(token);
    if (!record) return null;
    return {
      sub: record.userId,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: Math.floor(record.expiresAt.getTime() / 1000),
      issuer: this.options.issuer,
      audience: this.options.audience,
    };
  }
}

/**
 * RFC 7662 introspection: resolve a token to its active claims. Returns
 * `{ active: false }` for anything the issuer cannot verify (unknown, expired,
 * revoked, tampered) — never leaking *why* it failed.
 */
export async function introspectToken(token: string, issuer: TokenIssuer): Promise<IntrospectionResponse> {
  const claims = await issuer.verify(token);
  if (!claims) return { active: false };
  if (claims.expiresAt > 0 && claims.expiresAt * 1000 <= Date.now()) return { active: false };
  return {
    active: true,
    scope: claims.scopes.join(' '),
    clientId: claims.clientId,
    ...(claims.sub !== null ? { sub: claims.sub } : {}),
    ...(claims.expiresAt > 0 ? { exp: claims.expiresAt } : {}),
  };
}
