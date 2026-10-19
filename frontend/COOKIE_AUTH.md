# Frontend – Dùng cookie httpOnly thay cho localStorage

Branch: `claude/exciting-albattani-1q1dt8`

## Mục tiêu

- **Trước:** sau khi đăng nhập, frontend nhận `accessToken` và lưu vào `localStorage` (khi tick "Nhớ đăng nhập") hoặc `sessionStorage`. Axios interceptor tự gắn `Authorization: Bearer ...` vào mỗi request.
- **Sau:** backend set token vào cookie `httpOnly`. Frontend **không cầm token nữa**: không đọc, không lưu, không gắn header. Trình duyệt tự gửi cookie nhờ `withCredentials: true`.

Vì JavaScript không đọc được cookie `httpOnly`, frontend chỉ có một cách để biết người dùng đã đăng nhập hay chưa: gọi API `me`.

## Danh sách file thay đổi

| File | Thay đổi |
|---|---|
| `src/services/api.tsx` | Bỏ `tokenStorage`/`TOKEN_KEY` và interceptor gắn header; thêm `withCredentials: true` |
| `src/services/auth.tsx` | `login` gửi thêm `rememberMe` và không nhận token nữa; thêm `logout` |
| `src/Hooks/useAuth.tsx` | Lúc mở app luôn gọi `me()`; `login(user)`; `logout()` thành async, gọi API |
| `src/app/(auth)/login/page.tsx` | Gửi `rememberMe` lên server, gọi `login(res.data.user)` |
| `src/app/(main)/layout.tsx` | `await logout()` rồi mới chuyển trang |
| `src/services/mockAuth.ts` | Lưu phiên giả trong `mockSession` thay cho token; thêm `logout`; sửa import `AuthApi` |

---

## 1. `src/services/api.tsx`

```ts
// src/services/api.ts
import axios from 'axios';

const AUTH_PAGES = ['/login', '/signup', '/forgot-password'];

// Token nằm trong cookie httpOnly do backend set: FE không đọc/lưu token,
// trình duyệt tự gửi cookie nhờ withCredentials.
// "Nhớ đăng nhập" do backend quyết định (cookie 30 ngày hoặc session cookie).
const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  timeout: 20000,
  withCredentials: true,
});

// Cookie hết hạn / sai → đưa về trang đăng nhập (trừ khi đang ở trang login/signup/quên mật khẩu)
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401 && typeof window !== 'undefined') {
      if (!AUTH_PAGES.some((p) => window.location.pathname.startsWith(p))) window.location.href = '/login';
    }
    return Promise.reject(error);
  },
);

export default api;
```

## 2. `src/services/auth.tsx` (trong `realAuthApi`)

```ts
  // Server set cookie httpOnly chứa token, body chỉ trả user
  login: (body: { username: string; password: string; rememberMe: boolean }) =>
    api.post<ApiResponse<{ user: User }>>('/auth/login', body).then((r) => r.data),

  // Server xoá cookie
  logout: () => api.post<ApiResponse<null>>('/auth/logout').then((r) => r.data),
```

Các hàm khác (`register`, `forgotPassword`, `resetPassword`, `changePassword`, `me`) giữ nguyên.

## 3. `src/Hooks/useAuth.tsx`

```tsx
// src/hooks/useAuth.tsx
'use client';
import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { authApi, type User } from '@/services/auth';

interface AuthContextValue {
  user: User | null;
  loading: boolean;                                    // true khi đang hỏi server lúc mở app
  login: (user: User) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Mở app: JS không đọc được cookie httpOnly → luôn hỏi server user là ai
  useEffect(() => {
    authApi.me()
      .then((res) => { if (res.success) setUser(res.data); })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback((u: User) => setUser(u), []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();          // server xoá cookie
    } finally {
      setUser(null);
    }
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export default function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth phải dùng bên trong <AuthProvider>');
  return ctx;
}
```

Thay đổi API của hook:

| | Trước | Sau |
|---|---|---|
| `login` | `login(token, user, remember)` | `login(user)` |
| `logout` | `logout()` (đồng bộ) | `await logout()` (async, gọi server) |

## 4. `src/app/(auth)/login/page.tsx`

```ts
  const onSubmit = async ({ remember, ...body }: LoginForm) => {
    setAlert('');
    try {
      // remember gửi lên server: server quyết định cookie sống bao lâu
      const res = await authApi.login({ ...body, rememberMe: remember });
      if (!res.success) return setAlert(translateError(res.code));
      login(res.data.user);
      enqueueSnackbar(translate('login.success'), { variant: 'success' });
      router.replace('/');
    } catch (err) {
      setAlert(translateError(getErrorCode(err)));
    }
  };
```

Tên field gửi lên phải là `rememberMe`, khớp với `LoginDto` của backend. Backend bật `forbidNonWhitelisted`, nên gửi tên khác sẽ bị lỗi 400.

## 5. `src/app/(main)/layout.tsx`

```ts
  const handleLogout = async () => {
    await logout();
    router.replace('/login');
  };
```

## 6. `src/services/mockAuth.ts`

```ts
import type { ApiResponse, AuthApi, RegisterBody, User } from './auth';

const SESSION_KEY = 'mockSession'; // id user đang đăng nhập – đóng vai cookie của server thật

// Server thật đọc cookie; mock đọc id đã lưu lúc login
const currentUser = () => {
  const id = localStorage.getItem(SESSION_KEY);
  return loadUsers().find((u) => u.id === id);
};

export const mockAuthApi: AuthApi = {
  login: ({ username, password }) => {
    const user = loadUsers().find((u) => u.username === username && u.password === password);
    if (!user) return fail('WRONG_PASSWORD');
    localStorage.setItem(SESSION_KEY, user.id);
    return ok({ user: toUser(user) });
  },

  logout: () => {
    localStorage.removeItem(SESSION_KEY);
    return ok(null);
  },

  // ...register, forgotPassword, resetPassword, changePassword, me giữ nguyên
};
```

Mock chỉ dùng để dựng giao diện, nên lưu `mockSession` trong `localStorage` là được. Dòng import cũ (`authApi` thay vì `AuthApi`) gây ra 9 lỗi TypeScript, nay đã sửa.

---

## Cấu hình môi trường

### Dev

```env
NEXT_PUBLIC_API_URL=http://localhost:3000/api/v1
```

`localhost:3001` và `localhost:3000` được tính là cùng site, nên cookie chạy bình thường.

### Prod, frontend và backend khác domain (khuyên dùng proxy)

Dùng `rewrites` của Next để cookie thành first-party. Cách này chạy được cả trên Safari và không cần CORS:

```ts
// next.config.ts
async rewrites() {
  return [{ source: '/api/:path*', destination: `${process.env.BACKEND_URL}/api/:path*` }];
},
```

```env
NEXT_PUBLIC_API_URL=/api/v1
BACKEND_URL=https://api.your-domain.com
```

Nếu không dùng proxy thì backend phải đặt `COOKIE_SAMESITE=none` và chạy HTTPS.

## Dọn dẹp

Người dùng cũ có thể vẫn còn `accessToken` trong `localStorage`/`sessionStorage`. Token đó không còn được dùng nữa, nhưng nếu muốn xoá hẳn thì thêm đoạn sau vào `useEffect` của `AuthProvider` (chạy một lần là đủ):

```ts
localStorage.removeItem('accessToken');
sessionStorage.removeItem('accessToken');
```

## Đã kiểm tra

- `npx tsc --noEmit`: còn 2 lỗi, đều có từ trước và không liên quan:
  - `src/Components/AuthGuard.tsx` đang là file rỗng
  - `src/app/(main)/change-password/page.tsx`: prop `fontWeight` của `Typography`
- `npx eslint src`: 0 lỗi, chỉ có cảnh báo.
- **Chưa** chạy thử với backend thật.

## Việc còn tồn đọng (có từ trước, chưa sửa)

1. `authApi.me()` gọi `/auth/me`, nhưng backend chỉ có `/users/me`.
2. Frontend kiểm tra `res.success`, nhưng backend trả về `{ statusCode, message, data }`.

Phải sửa hai chỗ này thì đăng nhập mới chạy được từ đầu đến cuối.
