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
