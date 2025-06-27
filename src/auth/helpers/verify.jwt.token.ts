import * as jwt from 'jsonwebtoken';

/**
 * Verifies a JWT token using a given secret.
 * @param token - The JWT token to verify
 * @param secret - The secret to use for verification
 * @returns The decoded payload if valid
 * @throws Error if the token is invalid or expired
 */

export const verifyJwtToken = <T = any>(token: string, secret: string): T => {
  try {
    return jwt.verify(token, secret) as T;
  } catch (err) {
    throw new Error('Invalid or expired token');
  }
};
