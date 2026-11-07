import type { GrantHandler } from '../types';
import { AuthorizationCodeGrant } from './authorization-code';
import { ClientCredentialsGrant } from './client-credentials';
import { RefreshTokenGrant } from './refresh-token';

export { AuthorizationCodeGrant } from './authorization-code';
export { ClientCredentialsGrant } from './client-credentials';
export { RefreshTokenGrant } from './refresh-token';
export {
  assertGrantAllowed,
  authenticateClient,
  issueTokenPair,
  narrowScopes,
  resolveGrantedScopes,
  verifyPkceS256,
} from './shared';

/** Every grant the package ships, in registration order. */
export const defaultOAuthGrants = (): readonly GrantHandler[] => [
  new AuthorizationCodeGrant(),
  new ClientCredentialsGrant(),
  new RefreshTokenGrant(),
];
