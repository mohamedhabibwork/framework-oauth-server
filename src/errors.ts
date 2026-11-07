import { FrameworkError } from '@framework/core';

/**
 * RFC 6749 §5.2 error codes (plus `unsupported_response_type` from §4.1.2.1
 * and `access_denied`, which travels on a redirect rather than a JSON body).
 */
export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'access_denied';

/** The status an OAuth error maps to: `invalid_client` is 401, the rest 400. */
const statusFor = (code: OAuthErrorCode): 400 | 401 => (code === 'invalid_client' ? 401 : 400);

/**
 * Protocol-level failure carrying the RFC 6749 error code verbatim, so routes
 * can answer with the exact `{ error, error_description }` body the spec
 * mandates instead of the framework's generic error envelope. Descriptions are
 * deliberately generic — never disclose *why* a credential failed.
 */
export class OAuthError extends FrameworkError {
  readonly oauthCode: OAuthErrorCode;
  readonly status: 400 | 401;

  constructor(code: OAuthErrorCode, message: string, options?: ErrorOptions) {
    super(code.toUpperCase(), message, options);
    this.oauthCode = code;
    this.status = statusFor(code);
  }
}
