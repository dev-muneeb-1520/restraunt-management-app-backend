import { Role } from '@prisma/client';

export interface AuthPayload {
  sub: number;
  username: string;
  email: string;
  profilePictureUrl: string | null;
  role: Role;
  iat?: number;
  exp?: number;
}
