import { OAuthError } from '../errors';
import type { GrantDeps, GrantHandler, TokenRequest, TokenResponse } from '../types';
import { assertGrantAllowed, authenticateClient, issueTokenPair, narrowScopes } from './shared';

/**
 * RFC 6749 §6 refresh-token grant with rotation: the presented token is
 * revoked before a fresh pair is issued, so a stolen refresh token buys the
 * thief (at most) one redemption before the legitimate next refresh fails.
 * The refresh token stays bound to the client it was issued to — a token
 * replayed by another client is `invalid_grant`, never a fresh access token.
 */
export class RefreshTokenGrant implements GrantHandler {
  readonly type = 'refresh_token' as const;

  async handle(request: TokenRequest, deps: GrantDeps): Promise<TokenResponse> {
    const client = await authenticateClient(request, deps.clients);
    assertGrantAllowed(client, this.type);

    if (!request.refreshToken) {
      throw new OAuthError('invalid_request', 'refresh_token is required');
    }
    const record = await deps.tokens.findRefresh(request.refreshToken);
    if (!record) {
      throw new OAuthError('invalid_grant', 'The refresh token is invalid, expired or revoked');
    }
    if (record.clientId !== client.id) {
      throw new OAuthError('invalid_grant', 'The refresh token was issued to a different client');
    }

    const scopes = narrowScopes(request.scopes, record.scopes);
    // Rotate first: a replay of the old token must fail even if issuance below throws.
    await deps.tokens.revoke(request.refreshToken);
    return issueTokenPair(deps, { clientId: client.id, userId: record.userId, scopes, withRefresh: true });
  }
}
