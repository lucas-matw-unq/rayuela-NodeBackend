import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as fs from 'fs';
import * as path from 'path';

async function bootstrap() {
  // Rutas a certificados dentro de 'dist/certs' después de compilar
  const httpsOptions = {
    key: fs.readFileSync(path.resolve(__dirname, '../../src/certs/key.pem')),
    cert: fs.readFileSync(path.resolve(__dirname, '../../src/certs/cert.pem')),
  };

  const app = await NestFactory.create(AppModule, {
    httpsOptions, // Habilita HTTPS
    logger: ['error', 'warn', 'log'],
  });

  // Prefijo global
  app.setGlobalPrefix('api/v1');

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
