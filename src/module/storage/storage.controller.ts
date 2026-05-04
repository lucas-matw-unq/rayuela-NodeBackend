import { Controller, Get, Query, Res, NotFoundException } from '@nestjs/common';
import { StorageService } from './storage.service';
import { Response } from 'express';
import { Stream } from 'stream';

@Controller('storage')
export class StorageController {
  constructor(private readonly storageService: StorageService) {}

  @Get('file')
  async getFile(@Query('key') key: string, @Res() res: Response) {
    try {
      const { body, contentType } = await this.storageService.getFile(key);

      res.setHeader('Content-Type', contentType || 'application/octet-stream');

      if (body instanceof Stream) {
        body.pipe(res);
      } else if (body && typeof body.pipe === 'function') {
        body.pipe(res);
      } else {
        // Fallback for cases where it's not a stream (though S3 usually returns one)
        res.send(body);
      }
    } catch (error) {
      throw new NotFoundException('File not found');
    }
  }
}
