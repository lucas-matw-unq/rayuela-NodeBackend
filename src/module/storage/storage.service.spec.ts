import { Test, TestingModule } from '@nestjs/testing';
import { StorageService } from './storage.service';
import { ConfigService } from '@nestjs/config';
import { S3Client } from '@aws-sdk/client-s3';

jest.mock('@aws-sdk/client-s3');

describe('StorageService', () => {
  let service: StorageService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        StorageService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'S3_BUCKET') return 'test-bucket';
              return 'test-value';
            }),
          },
        },
      ],
    }).compile();

    service = module.get<StorageService>(StorageService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should upload a file and return the key', async () => {
    const mockFile = {
      originalname: 'test.png',
      buffer: Buffer.from('test'),
      mimetype: 'image/png',
    };

    const result = await service.uploadFile(mockFile, 'test-folder');

    expect(result).toContain('test-folder/');
    expect(result).toContain('.png');
    expect(S3Client.prototype.send).toHaveBeenCalled();
  });
});
