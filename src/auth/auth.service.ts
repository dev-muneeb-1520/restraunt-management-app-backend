import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { AuthPayload } from './interfaces/auth.payload.interface';
import { generateTokens } from './helpers/generate.jwt.tokens';
import { ConfigService } from '@nestjs/config';
import { verifyJwtToken } from './helpers/verify.jwt.token';
import { RefreshTokenDto } from './dto/refresh.token.dto';
import { CloudinaryService } from 'src/common/cloudinary/cloudinary.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private cloudinaryService: CloudinaryService,
  ) {}

  //register user only admins can do
  async register(registerDto: RegisterDto, file?: Express.Multer.File) {
    const { username, email, password, role } = registerDto;

    //check if the user exists
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ email }, { username }],
      },
    });

    if (existingUser) {
      throw new ConflictException(
        'User already exists! Please try with a different email or username',
      );
    }

    //hashing the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    let profilePictureMeta: any = null;

    if (file) {
      const uploaded = await this.cloudinaryService.uploadFile(file);
      profilePictureMeta = {
        originalName: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
        publicId: uploaded.public_id,
        secure_url: uploaded.secure_url,
      };
    }

    const newlyCreatedUser = await this.prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        role,
        refreshToken: '',
        profilePicture: profilePictureMeta,
      },
    });

    const { password: _, ...result } = newlyCreatedUser;
    return result;
  }

  //login the user and generate tokens
  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    //find the user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid Cradentials! Please try again');
    }

    //verify the password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw new UnauthorizedException('Invalid Cradentials! Please try again');
    }

    const profilePicture = user.profilePicture as ProfilePictureType;

    //creating the payload
    const payload: AuthPayload = {
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      profilePictureUrl: profilePicture?.secure_url || null,
    };

    const tokens = await generateTokens(
      payload,
      this.jwtService,
      this.configService,
    );

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        refreshToken: tokens.refreshToken,
      },
    });

    return tokens;
  }

  //refresh the token and generate the tokens again
  async refreshToken(refreshTokenDto: RefreshTokenDto) {
    try {
      const payload = verifyJwtToken<AuthPayload>(
        refreshTokenDto.refreshToken,
        this.configService.get<string>('REFRESH_TOKEN_SECRET') as string,
      );

      //find user by id
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });

      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('Access denied');
      }

      const profilePicture = user.profilePicture as ProfilePictureType;

      const newPayload: AuthPayload = {
        sub: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        profilePictureUrl: profilePicture?.secure_url || null,
      };

      const tokens = await generateTokens(
        newPayload,
        this.jwtService,
        this.configService,
      );

      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          refreshToken: tokens.refreshToken,
        },
      });

      return tokens;
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  //logout the user
  async logout(userId: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: null, //remove the refresh token for the logout
      },
    });

    return {
      message: 'Successfully logged out',
    };
  }
}
