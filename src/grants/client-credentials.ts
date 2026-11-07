import { OAuthError } from '../errors';
import type { GrantDeps, GrantHandler, TokenRequest, TokenResponse } from '../types';
import { assertGrantAllowed, authenticateClient, issueTokenPair, resolveGrantedScopes } from './shared';

const isRegisteredScope = (deps: GrantDeps) => (name: string) => deps.scopes.validate([name]).length === 0;

/**
 * RFC 6749 §4.4 client-credentials grant. The client is acting on its own
 * behalf: the access token has no subject (`sub` is absent), only confidential
 * clients may use it, and no refresh token is issued (§4.4.3 — there is no
 * owner session to refresh).
 */
export class ClientCredentialsGrant implements GrantHandler {
  readonly type = 'client_credentials' as const;

  async handle(request: TokenRequest, deps: GrantDeps): Promise<TokenResponse> {
    const client = await authenticateClient(request, deps.clients);
    assertGrantAllowed(client, this.type);

    if (client.type !== 'confidential') {
      throw new OAuthError('unauthorized_client', 'The client_credentials grant requires a confidential client');
    }

    // Requested scopes when given (validated against the registry and never
    // widened beyond the client's grant), otherwise everything it may hold.
    const scopes = resolveGrantedScopes(request.scopes, client, isRegisteredScope(deps));
    return issueTokenPair(deps, { clientId: client.id, userId: null, scopes, withRefresh: false });
  }
}
