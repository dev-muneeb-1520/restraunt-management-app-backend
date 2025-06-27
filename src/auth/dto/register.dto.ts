import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Role } from '@prisma/client';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class RegisterDto {
  @ApiPropertyOptional({
    description: 'URL of the profile picture',
    example: 'https://res.cloudinary.com/your-cloud/image/upload/profile.jpg',
  })
  @IsString({ message: 'Profile picture URL must be a string.' })
  @IsOptional()
  profilePictureUrl: string;

  @ApiProperty({
    description: 'Username of the user',
    example: 'john_doe',
    minLength: 6,
    maxLength: 50,
  })
  @IsString({ message: 'Username must be a string.' })
  @MinLength(6, { message: 'Username must be at least 6 characters long.' })
  @MaxLength(50, { message: 'Username must not exceed 50 characters.' })
  username: string;

  @ApiProperty({
    description: 'Valid email address of the user',
    example: 'john@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid email address.' })
  email: string;

  @ApiProperty({
    description: 'Password for the user account',
    example: 'securePass123',
    minLength: 6,
  })
  @IsString({ message: 'Password must be a string.' })
  @MinLength(6, { message: 'Password must be at least 6 characters long.' })
  password: string;

  @ApiProperty({
    description: 'Role of the user',
    enum: Role,
    example: Role.STAFF,
  })
  @IsEnum(Role, {
    message: 'Role must be one of the following: ADMIN, MANAGER, STAFF.',
  })
  role: Role;
}
