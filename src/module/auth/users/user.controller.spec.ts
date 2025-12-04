import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';

describe('UserController', () => {
  let controller: UserController;

  const mockUserService = {
    findByEmailOrUsername: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [{ provide: UserService, useValue: mockUserService }],
    }).compile();

    controller = module.get<UserController>(UserController);
  });

  it('debería estar definido', () => {
    expect(controller).toBeDefined();
  });

  describe('getUserInfo', () => {
    it('debería llamar a userService.findByEmailOrUsername con los argumentos correctos y retornar el resultado', async () => {
      const req = { user: { username: 'testuser' } };
      const expectedResult = {
        username: 'testuser',
        email: 'test@example.com',
      };
      mockUserService.findByEmailOrUsername.mockResolvedValue(expectedResult);

      const result = await controller.getUserInfo(req);

      expect(mockUserService.findByEmailOrUsername).toHaveBeenCalledWith(
        '',
        'testuser',
      );
      expect(result).toBe(expectedResult);
    });
  });
});
