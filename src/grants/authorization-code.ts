import { OAuthError } from '../errors';
import type { GrantDeps, GrantHandler, TokenRequest, TokenResponse } from '../types';
import { assertGrantAllowed, authenticateClient, issueTokenPair, narrowScopes, verifyPkceS256 } from './shared';

/**
 * RFC 6749 §4.1 authorization-code grant, with PKCE (RFC 7636) enforced for
 * public clients.
 *
 * The code is consumed atomically by the store, so a replayed code finds
 * `consumedAt` already set and fails as `invalid_grant`. When the code carries
 * a PKCE challenge the token request must present the matching verifier —
 * this is what lets a public client (which cannot keep a secret) authenticate.
 * Confidential clients still present their secret; a challenge is honoured for
 * them too when the authorization request carried one.
 */
export class AuthorizationCodeGrant implements GrantHandler {
  readonly type = 'authorization_code' as const;

  async handle(request: TokenRequest, deps: GrantDeps): Promise<TokenResponse> {
    const client = await authenticateClient(request, deps.clients);
    assertGrantAllowed(client, this.type);

    if (!request.code) {
      throw new OAuthError('invalid_request', 'code is required');
    }
    const record = await deps.codes.consume(request.code, client.id);
    if (!record) {
      throw new OAuthError('invalid_grant', 'The authorization code is invalid, expired or already used');
    }
    // RFC 6749 §4.1.3: if redirect_uri was in the authorization request it MUST be identical here.
    if (request.redirectUri && request.redirectUri !== record.redirectUri) {
      throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request');
    }

    if (record.codeChallenge) {
      if (!request.codeVerifier) {
        throw new OAuthError('invalid_grant', 'code_verifier is required for a PKCE-bound authorization code');
      }
      if (!verifyPkceS256(request.codeVerifier, record.codeChallenge)) {
        throw new OAuthError('invalid_grant', 'PKCE verification failed');
      }
    } else if (client.type === 'public') {
      // Defense in depth: the authorization endpoint never issues a challenge-less
      // code to a public client, so reaching here means the store was bypassed.
      throw new OAuthError('invalid_grant', 'Public clients must authorize with PKCE');
    }

    const scopes = narrowScopes(request.scopes, record.scopes);
    return issueTokenPair(deps, { clientId: client.id, userId: record.userId, scopes, withRefresh: true });
  }
}
