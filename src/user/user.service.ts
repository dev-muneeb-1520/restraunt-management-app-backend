import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { UpdateUserDto } from './dto/update.user.dto';
import * as bcrypt from 'bcrypt';
import { CloudinaryService } from 'src/common/cloudinary/cloudinary.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ProfilePictureType } from 'src/common/types/profile.picture.type';
import { AuthPayload } from 'src/common/interfaces/auth.payload.interface';
import { generateTokens } from 'src/common/helpers/generate.jwt.tokens';

@Injectable()
export class UserService {
  constructor(
    private prisma: PrismaService,
    private cloudinaryService: CloudinaryService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async find(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        password: true,
        profilePicture: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async update(
    userId: number,
    updateUserDto: UpdateUserDto,
    file?: Express.Multer.File,
  ) {
    // 1. Find the user first
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updateData: any = {};
    const oldProfile: ProfilePictureType | null = user.profilePicture as any;

    // 2. Handle password update
    if (updateUserDto.password) {
      const salt = await bcrypt.genSalt(10);
      updateData.password = await bcrypt.hash(updateUserDto.password, salt);
    }

    // 3. Handle profile picture update
    if (file) {
      if (oldProfile?.publicId) {
        await this.cloudinaryService.deleteFile(oldProfile.publicId);
      }

      const uploaded = await this.cloudinaryService.uploadFile(file);
      updateData.profilePicture = {
        originalName: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
        publicId: uploaded.public_id,
        secure_url: uploaded.secure_url,
      };
    }

    // 4. Handle username/email update
    if (updateUserDto.username) updateData.username = updateUserDto.username;
    if (updateUserDto.email) updateData.email = updateUserDto.email;

    // 5. Update user in DB
    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: updateData,
    });

    // 6. Prepare payload (always fetch latest values)
    const latestProfile = updatedUser.profilePicture as ProfilePictureType;
    const payload: AuthPayload = {
      sub: updatedUser.id,
      email: updatedUser.email,
      username: updatedUser.username,
      profilePictureUrl: latestProfile?.secure_url ?? null,
      role: updatedUser.role,
    };

    const updatedTokens = await generateTokens(
      payload,
      this.jwtService,
      this.configService,
    );

    // 7. Store new refresh token
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: updatedTokens.refreshToken,
      },
    });

    return updatedTokens;
  }

  async deleteProfilePicture(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const oldProfilePicture: ProfilePictureType | null =
      user.profilePicture as any;

    if (oldProfilePicture?.publicId) {
      await this.cloudinaryService.deleteFile(oldProfilePicture.publicId);
    }

    const deletedProfilePicture = await this.prisma.user.update({
      where: { id: userId },
      data: {
        profilePicture: {
          originalName: null,
          mimeType: null,
          size: null,
          publicId: null,
          secure_url: null,
        },
      },
    });

    const latestProfilePic =
      deletedProfilePicture.profilePicture as ProfilePictureType;

    //update the tokens
    const payload: AuthPayload = {
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      profilePictureUrl: latestProfilePic?.secure_url,
    };

    const updatedTokens = await generateTokens(
      payload,
      this.jwtService,
      this.configService,
    );

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: updatedTokens.refreshToken,
      },
    });

    return {
      message: 'Profile picture deleted successfully',
      tokens: updatedTokens,
    };
  }

  async deleteProfile(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const profilePicture: ProfilePictureType | null =
      user.profilePicture as any;

    if (profilePicture?.publicId) {
      try {
      } catch (error) {
        throw new InternalServerErrorException(
          'Failed to delete profile picture from cloudinary',
        );
      }
    }

    await this.prisma.user.delete({
      where: { id: userId },
    });

    return {
      message: 'User deleted successfully',
    };
  }
}
