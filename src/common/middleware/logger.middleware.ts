import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private logger = new Logger('HTTP');

  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl } = req;

    res.on('finish', () => {
      const { statusCode } = res;
      if (statusCode >= 500) {
        this.logger.error(`${method} ${originalUrl} ${statusCode}`);
      } else if (statusCode >= 400) {
        this.logger.warn(`${method} ${originalUrl} ${statusCode}`);
      } else {
        this.logger.log(`${method} ${originalUrl} ${statusCode}`);
      }
    });

    next();
  }
}
