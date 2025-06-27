import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAccessTokenStrategy } from './strategy/jwt.strategy';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { PrismaModule } from 'src/prisma/prisma.module';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    PrismaModule,
    PassportModule,
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('ACCESS_TOKEN_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtAccessTokenStrategy, JwtService],
  exports: [JwtAccessTokenStrategy, PassportModule],
})
export class AuthModule {}
