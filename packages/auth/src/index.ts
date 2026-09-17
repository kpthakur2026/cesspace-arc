/**
 * Interface definition for Authentication Engine.
 * Implementation target: RC-05.
 */
export interface AuthTokenClaims {
  clientId: string;
  clientType: string;
  deviceId: string;
  issuedAt: number;
  expiresAt: number;
}

export interface IAuthEngine {
  verifyToken(token: string): Promise<AuthTokenClaims>;
  generateSessionToken(claims: Omit<AuthTokenClaims, 'issuedAt' | 'expiresAt'>): Promise<string>;
}
