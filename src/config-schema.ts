import { z } from 'zod/v4';
import { ACCESS_TOKEN_TTL_SECONDS, AUTH_CODE_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS } from './constants';
import type { OAuthServerConfig } from './types';

/**
 * Validated shape of the application's `oauth` configuration section. Apps
 * compose it into their config schema: `oauth: oauthServerConfigSchema.prefault({})`.
 *
 * Disabled by default: an authorization server is an attack surface, so it is
 * never switched on implicitly (ADR-8, "never public by default").
 */
export const oauthServerConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    /** Token `iss`, and the base URL of the metadata document. */
    issuer: z.string().min(1).default('http://localhost:3000'),
    /** Token `aud`; resource servers set `auth.jwt.audience` to the same value. */
    audience: z.string().min(1).default('api'),
    /** Access-token lifetime in seconds (default one hour). */
    accessTokenTtlSeconds: z.number().int().positive().default(ACCESS_TOKEN_TTL_SECONDS),
    /** Refresh-token lifetime in seconds (default 30 days). */
    refreshTokenTtlSeconds: z.number().int().positive().default(REFRESH_TOKEN_TTL_SECONDS),
    /** Authorization-code lifetime in seconds (default one minute). */
    authCodeTtlSeconds: z.number().int().positive().default(AUTH_CODE_TTL_SECONDS),
    /** Scopes granted when a client requests none. */
    defaultScopes: z.array(z.string().min(1)).default([]),
  })
  .prefault({});

/** Resolved defaults, exported for tests and documentation. */
export const defaultOAuthServerConfig: OAuthServerConfig = oauthServerConfigSchema.parse({});
