import type { CookieOptions } from 'express';

// Tên cookie chứa JWT – dùng chung cho controller (set/clear) và JwtStrategy (đọc)
export const ACCESS_TOKEN_COOKIE = 'accessToken';

const REMEMBER_ME_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // khớp với expiresIn '30d' trong AuthService

/**
 * Cấu hình cookie theo môi trường:
 * - Dev (localhost:3001 → localhost:3000): cùng site → sameSite 'lax', không cần HTTPS
 * - Prod FE/BE khác domain: đặt COOKIE_SAMESITE=none (bắt buộc HTTPS, secure tự bật)
 */
export function baseCookieOptions(): CookieOptions {
  const sameSite = (process.env.COOKIE_SAMESITE ?? 'lax') as 'lax' | 'strict' | 'none';
  return {
    httpOnly: true, // JS phía FE không đọc được → chống XSS lấy token
    secure: process.env.NODE_ENV === 'production' || sameSite === 'none',
    sameSite,
    path: '/',
  };
}

// rememberMe = true → cookie sống 30 ngày; false → session cookie, đóng trình duyệt là mất
export function accessTokenCookieOptions(rememberMe?: boolean): CookieOptions {
  return {
    ...baseCookieOptions(),
    ...(rememberMe ? { maxAge: REMEMBER_ME_MAX_AGE_MS } : {}),
  };
}
