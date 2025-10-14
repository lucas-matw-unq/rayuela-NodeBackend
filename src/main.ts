import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log'],
  });

  // Prefijo global
  app.setGlobalPrefix('v1');

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
