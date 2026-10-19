# Backend – Chuyển JWT sang cookie httpOnly

Branch: `claude/exciting-albattani-1q1dt8`

## Mục tiêu

- **Trước:** khi đăng nhập, backend trả `accessToken` trong body. Frontend tự lưu token vào `localStorage`/`sessionStorage` và tự gắn header `Authorization: Bearer ...` vào mỗi request.
- **Sau:** backend set token vào cookie `httpOnly` tên `accessToken`, trình duyệt tự gửi cookie này theo mỗi request. JavaScript phía frontend không đọc được token, nhờ đó chống được việc mã XSS lấy cắp token.

## Danh sách file thay đổi

| File | Thay đổi |
|---|---|
| `package.json`, `package-lock.json` | Thêm `cookie-parser` (dependencies) và `@types/cookie-parser` (devDependencies) |
| `.env.example` | Thêm `COOKIE_SAMESITE=lax` |
| `src/modules/auth/auth.cookie.ts` | **Mới.** Chứa tên cookie và cấu hình cookie dùng chung |
| `src/main.ts` | Thêm `app.use(cookieParser())` |
| `src/modules/auth/strategies/jwt.strategy.ts` | Đọc token từ cookie trước, sau đó mới tới header Bearer |
| `src/modules/auth/auth.controller.ts` | `login` set cookie; `logout` và `change-password` xoá cookie |
| `src/modules/auth/auth.service.ts` | `logout()` bỏ tham số `userId` không dùng |

Cài package:

```bash
npm install cookie-parser
npm install -D @types/cookie-parser
```

---

## 1. `src/modules/auth/auth.cookie.ts` (file mới)

```ts
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
```

## 2. `src/main.ts`

```ts
import cookieParser from 'cookie-parser';
// ...

  // Đọc cookie (req.cookies) – JWT được gửi qua cookie httpOnly
  app.use(cookieParser());

  // CORS – credentials: true để trình duyệt gửi kèm cookie; origin phải là domain cụ thể, không được '*'
  app.enableCors({
    origin: process.env.FRONTEND_URL ?? 'http://localhost:3001',
    credentials: true,
  });
```

> CORS đã có sẵn `credentials: true` và `origin` cụ thể, nên không cần sửa. Không được đổi `origin` thành `'*'`, vì khi đó trình duyệt sẽ không gửi cookie.

## 3. `src/modules/auth/strategies/jwt.strategy.ts`

```ts
import type { Request } from 'express';
import { ACCESS_TOKEN_COOKIE } from '../auth.cookie.js';
// ...

    super({
      // Ưu tiên cookie httpOnly (FE); vẫn nhận header Bearer để test bằng Swagger/Postman
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => req?.cookies?.[ACCESS_TOKEN_COOKIE] ?? null,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET', 'default-secret-change-me'),
    });
```

## 4. `src/modules/auth/auth.controller.ts`

Import thêm:

```ts
import { /* ...các import cũ... */ Res } from '@nestjs/common';
import type { Response } from 'express';
import {
  ACCESS_TOKEN_COOKIE,
  accessTokenCookieOptions,
  baseCookieOptions,
} from './auth.cookie.js';
```

### Đăng nhập: set cookie, không trả token trong body

```ts
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, ...rest } = await this.authService.login(dto);
    res.cookie(ACCESS_TOKEN_COOKIE, accessToken, accessTokenCookieOptions(dto.rememberMe));
    return rest; // không trả token trong body nữa
  }
```

Response mới: `{ statusCode, message, data: { expiresIn, user } }`. Trong `data` không còn `accessToken`.

### Đăng xuất: xoá cookie, cho phép gọi khi chưa đăng nhập

```ts
  // Public: token hết hạn/không hợp lệ vẫn phải xoá được cookie
  @Public()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Đăng xuất',
    description: 'Xoá cookie accessToken. Không yêu cầu token hợp lệ.',
  })
  // ...@ApiResponse 200 giữ nguyên
  logout(@Res({ passthrough: true }) res: Response) {
    // Option phải khớp lúc set (path, sameSite, secure) thì trình duyệt mới xoá
    res.clearCookie(ACCESS_TOKEN_COOKIE, baseCookieOptions());
    return this.authService.logout();
  }
```

Bỏ `@UseGuards(JwtAuthGuard)`, `@ApiBearerAuth()` và `@ApiResponse` 401. Nếu vẫn bắt buộc token hợp lệ thì khi cookie đã hết hạn sẽ không gọi logout được, và cookie đó nằm lại trong trình duyệt.

### Đổi mật khẩu: xoá cookie sau khi đổi thành công

```ts
  async changePassword(
    @CurrentUser() user: { id: number },
    @Body() dto: ChangePasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.changePassword(user.id, dto);
    // Token cũ đã bị vô hiệu → xoá cookie luôn (FORCE_LOGOUT)
    res.clearCookie(ACCESS_TOKEN_COOKIE, baseCookieOptions());
    return result;
  }
```

## 5. `src/modules/auth/auth.service.ts`

```ts
  // trước: async logout(_userId: number) {
  async logout() {
    return {
      message: 'Đăng xuất thành công.',
      action: 'CLEAR_TOKEN',
    };
  }
```

## 6. `.env.example`

```env
JWT_EXPIRES_IN=8h
# SameSite của cookie accessToken: lax (FE/BE cùng site) | none (khác domain, bắt buộc HTTPS)
COOKIE_SAMESITE=lax
```

---

## Cấu hình theo môi trường

| Tình huống | `COOKIE_SAMESITE` | `secure` |
|---|---|---|
| Dev: `localhost:3001` → `localhost:3000` (khác port vẫn tính là cùng site) | `lax` | tắt |
| Prod, cùng domain gốc (`app.x.com` / `api.x.com`) | `lax` | bật tự động khi `NODE_ENV=production` |
| Prod, khác domain hẳn | `none` | bật tự động (bắt buộc HTTPS) |

Nhớ đặt `FRONTEND_URL` đúng domain của frontend để CORS cho phép gửi cookie.

## Ghi nhớ đăng nhập (`rememberMe` trong `LoginDto`)

| `rememberMe` | JWT `expiresIn` | Cookie |
|---|---|---|
| `true` | `30d` | `maxAge` 30 ngày |
| `false` / không gửi | `JWT_EXPIRES_IN` (mặc định `8h`) | Session cookie, đóng trình duyệt là mất |

## Swagger / Postman

- Header `Authorization: Bearer <token>` vẫn dùng được.
- Swagger UI chạy cùng origin với API (`localhost:3000`), nên sau khi gọi `/auth/login` trên Swagger, cookie được gửi tự động cho các request sau.

## Đã kiểm tra

- `npx tsc --noEmit`: không lỗi.
- `npm run lint`: chỉ còn cảnh báo import không dùng, có từ trước, không liên quan đến thay đổi này.
- **Chưa** chạy thử với database thật.

## Việc còn tồn đọng (có từ trước, chưa sửa)

1. Frontend gọi `GET /auth/me`, nhưng backend chỉ có `GET /users/me`.
2. Frontend kiểm tra `res.success`, nhưng `ResponseInterceptor` trả về `{ statusCode, message, data }` và không có field `success`.

Phải sửa hai chỗ này thì luồng đăng nhập mới chạy được từ đầu đến cuối.
