import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { AuthService } from './auth.service.js';
import {
  LoginDto,
  ChangePasswordDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  VerifyEmailOtpDto,
  ConfirmEmailChangeDto,
} from './dto/auth.dto.js';
import { Public } from '../../commons/decorators/public.decorator.js';
import { CurrentUser } from '../../commons/decorators/current-user.decorator.js';
import { JwtAuthGuard } from '../../commons/guards/jwt-auth.guard.js';
import {
  ACCESS_TOKEN_COOKIE,
  accessTokenCookieOptions,
  baseCookieOptions,
} from './auth.cookie.js';

@ApiTags('Auth – Xác thực')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ─── 1. ĐĂNG NHẬP ─────────────────────────────────────────────────────────
  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Đăng nhập hệ thống',
    description:
      'Xác thực tài khoản, set JWT vào cookie httpOnly "accessToken" và trả về thông tin người dùng.',
  })
  @ApiResponse({
    status: 200,
    description: 'Đăng nhập thành công. Token nằm trong cookie, body chỉ có thông tin user.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          expiresIn: '8h',
          user: {
            id: 1,
            username: 'admin',
            fullName: 'Quản trị viên',
            email: 'admin@example.com',
            roleId: 1,
            avatarUrl: null,
            isActive: true,
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bỏ trống tên đăng nhập hoặc mật khẩu.',
    schema: {
      example: {
        statusCode: 400,
        message: 'Vui lòng nhập đầy đủ thông tin.',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/login',
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Tài khoản hoặc mật khẩu không đúng.',
    schema: {
      example: {
        statusCode: 401,
        message: 'Tài khoản hoặc mật khẩu không đúng. Xin vui lòng thử lại.',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/login',
      },
    },
  })
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, ...rest } = await this.authService.login(dto);
    res.cookie(ACCESS_TOKEN_COOKIE, accessToken, accessTokenCookieOptions(dto.rememberMe));
    return rest; // không trả token trong body nữa
  }

  // ─── 2. ĐĂNG XUẤT ─────────────────────────────────────────────────────────
  // Public: token hết hạn/không hợp lệ vẫn phải xoá được cookie
  @Public()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Đăng xuất',
    description: 'Xoá cookie accessToken. Không yêu cầu token hợp lệ.',
  })
  @ApiResponse({
    status: 200,
    description: 'Đăng xuất thành công.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          message: 'Đăng xuất thành công.',
          action: 'CLEAR_TOKEN',
        },
      },
    },
  })
  logout(@Res({ passthrough: true }) res: Response) {
    // Option phải khớp lúc set (path, sameSite, secure) thì trình duyệt mới xoá
    res.clearCookie(ACCESS_TOKEN_COOKIE, baseCookieOptions());
    return this.authService.logout();
  }

  // ─── 3. ĐỔI MẬT KHẨU (khi đã đăng nhập) ─────────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Đổi mật khẩu',
    description:
      'Sau khi đổi thành công, toàn bộ token cũ sẽ bị vô hiệu hóa. ' +
      'Client phải xóa token và chuyển người dùng về trang đăng nhập.',
  })
  @ApiResponse({
    status: 200,
    description: 'Đổi mật khẩu thành công. action=FORCE_LOGOUT báo client đăng xuất.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          message: 'Đổi mật khẩu thành công. Vui lòng đăng nhập lại.',
          action: 'FORCE_LOGOUT',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Mật khẩu cũ sai / Mật khẩu mới không khớp / Trùng mật khẩu cũ',
    schema: {
      example: {
        statusCode: 400,
        message: 'Mật khẩu hiện tại không đúng',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/change-password',
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Chưa đăng nhập hoặc token đã hết hạn',
    schema: {
      example: {
        statusCode: 401,
        message: 'Bạn cần đăng nhập để thực hiện thao tác này',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/change-password',
      },
    },
  })
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

  // ─── 4. QUÊN MẬT KHẨU – BƯỚC 1: Gửi OTP ──────────────────────────────────
  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Forgot Password – Step 1] Gửi mã OTP khôi phục mật khẩu qua email',
    description: 'Kiểm tra email trong hệ thống và gửi mã OTP 6 số qua email.',
  })
  @ApiResponse({
    status: 200,
    description: 'Gửi mã OTP thành công.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          message: 'Gửi email thành công.',
          expiresInMinutes: 5,
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Lỗi xác thực dữ liệu đầu vào (Validation Error: Email không đúng định dạng hoặc để trống).',
    schema: {
      example: {
        statusCode: 400,
        message: 'Vui lòng nhập đúng định dạng email (ví dụ: username@domain.com).',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/forgot-password',
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Không tìm thấy tài khoản (Email chưa được đăng ký trong hệ thống).',
    schema: {
      example: {
        statusCode: 404,
        message: 'Email chưa được đăng ký. Xin vui lòng thử lại.',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/forgot-password',
      },
    },
  })
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  // ─── 4b. QUÊN MẬT KHẨU – BƯỚC 2: Xác nhận OTP + Đặt mật khẩu mới ─────────
  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Forgot Password – Step 2] Xác nhận OTP và đặt mật khẩu mới',
    description:
      'Người dùng cung cấp: email, OTP 6 số, mật khẩu mới và xác nhận mật khẩu. ' +
      'Sau khi thành công, trả về action=REDIRECT_TO_LOGIN để chuyển hướng về trang đăng nhập.',
  })
  @ApiResponse({
    status: 200,
    description: 'Khôi phục thành công. Báo client chuyển về màn hình đăng nhập.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          message: 'Đặt lại mật khẩu thành công. Vui lòng đăng nhập lại bằng mật khẩu mới.',
          action: 'REDIRECT_TO_LOGIN',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Mã OTP không đúng, đã hết hạn hoặc mật khẩu xác nhận không khớp.',
    schema: {
      example: {
        statusCode: 400,
        message: 'Mã OTP không chính xác hoặc đã hết hạn',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/reset-password',
      },
    },
  })
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPasswordWithOtp(dto);
  }

  // ─── 5. THAY ĐỔI EMAIL – BƯỚC 1: Gửi OTP về email cũ ────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('request-email-change')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[Email Change – Step 1] Gửi OTP về email hiện tại để xác thực',
    description: 'Gửi mã OTP 6 số về email hiện tại của tài khoản đang đăng nhập.',
  })
  @ApiResponse({
    status: 200,
    description: 'Mã OTP đã được gửi về email hiện tại.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          message: 'Mã OTP đã được gửi đến email hiện tại của bạn. Vui lòng kiểm tra hộp thư.',
          expiresInMinutes: 5,
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Tài khoản chưa có email để gửi OTP.',
    schema: {
      example: {
        statusCode: 400,
        message: 'Tài khoản chưa có email để gửi mã OTP',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/request-email-change',
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Chưa đăng nhập.',
    schema: {
      example: {
        statusCode: 401,
        message: 'Bạn cần đăng nhập để thực hiện thao tác này',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/request-email-change',
      },
    },
  })
  requestEmailChangeOtp(@CurrentUser() user: { id: number }) {
    return this.authService.requestEmailChangeOtp(user.id);
  }

  // ─── 6. THAY ĐỔI EMAIL – BƯỚC 2: Xác minh OTP ───────────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('verify-email-otp')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[Email Change – Step 2] Xác minh mã OTP 6 số',
    description: 'Xác minh mã OTP người dùng nhận được ở bước 1.',
  })
  @ApiResponse({
    status: 200,
    description: 'OTP hợp lệ. Có thể tiến hành nhập email mới.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          message: 'Xác thực mã OTP thành công. Bạn có thể tiến hành đổi email.',
          verified: true,
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'OTP sai hoặc đã hết hạn.',
    schema: {
      example: {
        statusCode: 400,
        message: 'Mã OTP không chính xác hoặc đã hết hạn',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/verify-email-otp',
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Chưa đăng nhập.',
    schema: {
      example: {
        statusCode: 401,
        message: 'Bạn cần đăng nhập để thực hiện thao tác này',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/verify-email-otp',
      },
    },
  })
  verifyEmailOtp(
    @CurrentUser() user: { id: number },
    @Body() dto: VerifyEmailOtpDto,
  ) {
    return this.authService.verifyEmailOtp(user.id, dto);
  }

  // ─── 7. THAY ĐỔI EMAIL – BƯỚC 3: Xác nhận email mới ─────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('confirm-email-change')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[Email Change – Step 3] Nhập email mới và lưu vào hệ thống',
    description: 'Gửi kèm OTP đã xác minh ở bước 2 để bảo vệ endpoint này.',
  })
  @ApiResponse({
    status: 200,
    description: 'Cập nhật email thành công.',
    schema: {
      example: {
        statusCode: 200,
        message: 'Thành công',
        data: {
          message: 'Cập nhật email thành công.',
          newEmail: 'newemail@example.com',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Mã OTP không hợp lệ hoặc đã hết hiệu lực.',
    schema: {
      example: {
        statusCode: 400,
        message: 'Mã OTP không hợp lệ.',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/confirm-email-change',
      },
    },
  })
  @ApiResponse({
    status: 409,
    description: 'Xung đột dữ liệu – Email mới đã được sử dụng bởi tài khoản khác.',
    schema: {
      example: {
        statusCode: 409,
        message: 'Email này đã được sử dụng bởi tài khoản khác.',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/confirm-email-change',
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Chưa đăng nhập.',
    schema: {
      example: {
        statusCode: 401,
        message: 'Bạn cần đăng nhập để thực hiện thao tác này',
        timestamp: '2026-10-18T16:00:00.000Z',
        path: '/api/v1/auth/confirm-email-change',
      },
    },
  })
  confirmEmailChange(
    @CurrentUser() user: { id: number },
    @Body() dto: ConfirmEmailChangeDto,
  ) {
    return this.authService.confirmEmailChange(user.id, dto);
  }
}
