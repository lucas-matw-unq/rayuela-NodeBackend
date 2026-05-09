import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';
import { MulterError } from 'multer';

/**
 * Maps Multer errors (raised inside `FilesInterceptor`) into clean HTTP
 * responses so the mobile client can classify them as permanent
 * failures instead of opaque 500s.
 *
 * Currently handled:
 *   * `LIMIT_FILE_SIZE`   → 413 Payload Too Large
 *   * `LIMIT_FILE_COUNT`  → 413
 *   * `LIMIT_UNEXPECTED_FILE` (wrong field name or MIME rejection) → 400
 *   * everything else     → 400 with the underlying message
 */
@Catch(MulterError)
export class MulterExceptionFilter implements ExceptionFilter<MulterError> {
  private readonly logger = new Logger(MulterExceptionFilter.name);

  catch(exception: MulterError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();

    const status = (() => {
      switch (exception.code) {
        case 'LIMIT_FILE_SIZE':
        case 'LIMIT_FILE_COUNT':
          return HttpStatus.PAYLOAD_TOO_LARGE; // 413
        case 'LIMIT_UNEXPECTED_FILE':
        case 'LIMIT_PART_COUNT':
        case 'LIMIT_FIELD_KEY':
        case 'LIMIT_FIELD_VALUE':
        case 'LIMIT_FIELD_COUNT':
        default:
          return HttpStatus.BAD_REQUEST; // 400
      }
    })();

    this.logger.warn(
      `Upload rejected (${exception.code}) on ${ctx.getRequest().originalUrl}`,
    );

    res.status(status).json({
      statusCode: status,
      code: exception.code,
      message: exception.message,
      // Echo the field name so the client can highlight the offending
      // input when this fires from a multi-field form.
      field: exception.field,
    });
  }
}
