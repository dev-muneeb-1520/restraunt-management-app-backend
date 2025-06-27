import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthPayload } from '../interfaces/auth.payload.interface';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtAccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('ACCESS_TOKEN_SECRET') as string,
    });
  }

  async validate(payload: AuthPayload) {
    return payload;
  }
}
