import {
  Body,
  Controller,
  Post,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh.token.dto';
import { GetUser } from './decorators/get.user.decorator';
import { AuthPayload } from './interfaces/auth.payload.interface';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import {
  ApiBearerAuth,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiBody,
} from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('Auth') // Group all endpoints in Swagger under "Auth"
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN')
  @Post('register')
  @UseInterceptors(FileInterceptor('profilePicture'))
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        profilePicture: {
          type: 'string',
          format: 'binary',
        },
        username: { type: 'string' },
        email: { type: 'string' },
        password: { type: 'string' },
        role: { type: 'string', enum: ['ADMIN', 'MANAGER', 'STAFF', 'CHEF'] },
      },
    },
  })
  @ApiBearerAuth('JWT-auth') //this tells the swagger to include the token
  @ApiOperation({ summary: 'Register a new user (ADMIN only)' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 409, description: 'User already exists' })
  @ApiResponse({ status: 403, description: 'Forbidden: Only admins allowed' })
  async register(
    @UploadedFile() file: Express.Multer.File,
    @Body() registerDto: RegisterDto,
  ) {
    return this.authService.register(registerDto, file);
  }

  @Post('login')
  @ApiOperation({ summary: 'Authenticate user and return JWT tokens' })
  @ApiResponse({ status: 200, description: 'Login successful, tokens issued' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('refresh-token')
  @ApiOperation({ summary: 'Refresh access and refresh tokens' })
  @ApiResponse({ status: 200, description: 'Tokens refreshed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Logout user and clear refresh token' })
  @ApiResponse({ status: 200, description: 'User logged out successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized: Invalid token' })
  async logout(@GetUser() user: AuthPayload) {
    return this.authService.logout(user.sub);
  }
}
