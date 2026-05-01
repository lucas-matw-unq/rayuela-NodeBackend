/**
 * How long an access token (JWT) stays valid, in seconds.
 *
 * Single source of truth shared by:
 *   - `JwtModule.register({ signOptions: { expiresIn } })` in auth.module.ts
 *   - the `expires_in` field returned by `AuthService.login()`
 *
 * Keep them coupled — drift here causes the client to refresh too late.
 */
export const ACCESS_TOKEN_TTL_SECONDS = 60 * 60; // 1 hour

/**
 * How long a refresh token stays valid, in days.
 *
 * Instagram-style infinite-session: ~60–90 days. If a user doesn't open the
 * app for this long, they'll be forced to log in again.
 */
export const REFRESH_TOKEN_TTL_DAYS = 90;

/**
 * Refresh tokens are shaped as `${userId}${SEPARATOR}${secret}` so the server
 * can locate the owner without an extra lookup field. The userId portion is a
 * Mongo ObjectId (24 hex chars, no dots) and the secret is a uuid v4 (hex +
 * dashes, no dots), so splitting on the first '.' is unambiguous.
 */
export const REFRESH_TOKEN_SEPARATOR = '.';
