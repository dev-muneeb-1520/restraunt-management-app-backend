import { JwtService } from '@nestjs/jwt';
import { AuthPayload } from '../interfaces/auth.payload.interface';
import { TokenPair } from '../interfaces/token.pair.interface';
import { ConfigService } from '@nestjs/config';

export const generateTokens = async (
  payload: AuthPayload,
  jwtService: JwtService,
  configService: ConfigService,
): Promise<TokenPair> => {
  const accessToken = await jwtService.signAsync(payload, {
    secret: configService.get<string>('ACCESS_TOKEN_SECRET') as string,
    expiresIn: '15m',
  });

  const refreshToken = await jwtService.signAsync(payload, {
    secret: configService.get<string>('REFRESH_TOKEN_SECRET'),
    expiresIn: '7d',
  });

  return {
    accessToken: accessToken,
    refreshToken: refreshToken,
  };
};
