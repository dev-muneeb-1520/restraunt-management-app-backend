import { Inject, Injectable } from '@nestjs/common';
import { UploadApiErrorResponse, UploadApiResponse } from 'cloudinary';
import * as streamifier from 'streamifier';

@Injectable()
export class CloudinaryService {
  constructor(
    @Inject('CLOUDINARY')
    private readonly cloudinary: any,
  ) {}

  uploadFile(file: Express.Multer.File): Promise<UploadApiResponse> {
    return new Promise<UploadApiResponse>((resolve, reject) => {
      const uploadStream = this.cloudinary.uploader.upload_stream(
        {
          folder: 'restaurant-profiles',
          resource_type: 'auto',
        },
        (error: UploadApiErrorResponse, result: UploadApiResponse) => {
          if (error) reject(error);
          resolve(result);
        },
      );
      streamifier.createReadStream(file.buffer).pipe(uploadStream);
    });
  }

  async deleteFile(publicId: string): Promise<any> {
    return this.cloudinary.uploader.destroy(publicId);
  }
}
