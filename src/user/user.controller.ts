import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Patch,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { GetUser } from 'src/auth/decorators/get.user.decorator';
import { AuthPayload } from 'src/common/interfaces/auth.payload.interface';
import { UpdateUserDto } from './dto/update.user.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';

@ApiTags('Users')
@ApiBearerAuth('JWT-auth')
@UseGuards(AuthGuard('jwt'))
@Controller('user')
export class UserController {
  constructor(private readonly userSerivce: UserService) {}

  @Get('profile')
  @ApiOperation({ summary: 'Get logged in user profile' })
  @ApiResponse({ status: 200, description: 'Profile retrieved' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async getProfile(@GetUser() user: AuthPayload) {
    return this.userSerivce.find(user.sub);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN', 'CHEF', 'MANAGER', 'STAFF')
  @UseInterceptors(FileInterceptor('profilePicture'))
  @ApiConsumes('multipart/form-data')
  @ApiBody({ type: UpdateUserDto })
  @ApiResponse({ status: 200, description: 'User updated successfullty' })
  @ApiResponse({ status: 404, description: 'User not authorized or not found' })
  @ApiOperation({ summary: 'Update the user profile' })
  @ApiBearerAuth('JWT-auth')
  @Patch('update/profile')
  async updateProfile(
    @GetUser() user: AuthPayload,
    @Body() updateUserDto: UpdateUserDto,
    @UploadedFile() file: Express.Multer.File,
  ) {
    return this.userSerivce.update(user.sub, updateUserDto, file);
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiResponse({
    status: 200,
    description: 'User profile picture deleted successfullty',
  })
  @ApiResponse({ status: 404, description: 'User not authorized or not found' })
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'User can delete his profile picture' })
  @Delete('delete/profilePicture')
  async deleteProfilePicture(@GetUser() user: AuthPayload) {
    return this.userSerivce.deleteProfilePicture(user.sub);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN', 'MANAGER')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Delete any user by ID (Admin or Manager only)' })
  @ApiParam({
    name: 'id',
    type: Number,
    description: 'ID of the user to delete',
  })
  @ApiResponse({ status: 200, description: 'User deleted successfully' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden: Only admins or managers can delete users',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @Delete('/delete-profile/:id')
  async deleteProfile(@Param('id', ParseIntPipe) id: number) {
    return this.userSerivce.deleteProfile(id);
  }
}
