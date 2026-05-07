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

  // Convert Multer's framework-level errors (file too big, wrong MIME)
  // into clean HTTP responses so the mobile outbox can classify them.
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
