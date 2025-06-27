import { IsEmail, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    description: 'Registered email address of the user',
    example: 'john@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid email address.' })
  email: string;

  @ApiProperty({
    description: 'Password for the user account',
    example: 'securePass123',
  })
  @IsString({ message: 'Password must be a string.' })
  password: string;
}
