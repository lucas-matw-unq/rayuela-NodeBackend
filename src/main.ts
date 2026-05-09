import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { MulterExceptionFilter } from './common/filters/multer-exception.filter';
import { RequestMethod } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log'],
  });

  // Prefijo global
  app.setGlobalPrefix('v1', {
    exclude: [
      { path: 'health', method: RequestMethod.GET },
      { path: 'health', method: RequestMethod.HEAD },
    ],
  });

  // Convert Multer framework-level errors (for example, file too big)
  // into clean HTTP responses so the mobile outbox can classify them.
  // Note: MIME rejections raised as BadRequestException are not handled
  // by MulterExceptionFilter unless they are normalized elsewhere.
  app.useGlobalFilters(new MulterExceptionFilter());

  // Configuración de Swagger
  const config = new DocumentBuilder()
    .setTitle('Rayuela backend API')
    .setDescription('API para la app de rayuela')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  // CORS
  app.enableCors();
  await app.listen(3000);
}

bootstrap();
