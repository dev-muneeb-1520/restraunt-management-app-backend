import { ApiProperty } from "@nestjs/swagger";
import { IsString } from "class-validator";

// dto/refresh-token.dto.ts
export class RefreshTokenDto {
  @ApiProperty({ description: 'Refresh token', example: 'asdsadsadasdasdsadsad... <token>' })
  @IsString()
  refreshToken: string;
}
