import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { UserRole } from './users/user.schema';

describe('AuthController', () => {
    let controller: AuthController;
    let service: AuthService;

    const mockAuthService = {
        validateUser: jest.fn(),
        login: jest.fn(),
        recoverPassword: jest.fn(),
        forgotPassword: jest.fn(),
        verifyEmail: jest.fn(),
        register: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [AuthController],
            providers: [
                { provide: AuthService, useValue: mockAuthService },
            ],
        }).compile();

        controller = module.get<AuthController>(AuthController);
        service = module.get<AuthService>(AuthService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('login', () => {
        it('should login successfully', async () => {
            const body = { username: 'test', password: 'password' };
            const user = { username: 'test' };
            mockAuthService.validateUser.mockResolvedValue(user);
            mockAuthService.login.mockResolvedValue({ access_token: 'token' });

            const result = await controller.login(body);
            expect(result).toEqual({ access_token: 'token' });
        });

        it('should throw BadRequestException if missing fields', async () => {
            await expect(controller.login({ username: '', password: '' })).rejects.toThrow(BadRequestException);
        });

        it('should throw UnauthorizedException if invalid credentials', async () => {
            mockAuthService.validateUser.mockResolvedValue(null);
            await expect(controller.login({ username: 'test', password: 'wrong' })).rejects.toThrow(UnauthorizedException);
        });
    });

    describe('recoverPassword', () => {
        it('should recover password successfully', async () => {
            const body = { token: 'token', newPassword: 'new' };
            await controller.recoverPassword(body);
            expect(service.recoverPassword).toHaveBeenCalledWith('token', 'new');
        });

        it('should throw BadRequestException if missing fields', async () => {
            await expect(controller.recoverPassword({ token: '', newPassword: '' })).rejects.toThrow(BadRequestException);
        });
    });

    describe('forgotPassword', () => {
        it('should send forgot password email', async () => {
            await controller.forgotPassword({ email: 'test@test.com' });
            expect(service.forgotPassword).toHaveBeenCalledWith('test@test.com');
        });

        it('should throw BadRequestException if missing email', async () => {
            await expect(controller.forgotPassword({ email: '' })).rejects.toThrow(BadRequestException);
        });
    });

    describe('verifyToken', () => {
        it('should verify token successfully', async () => {
            const user = { username: 'test' };
            mockAuthService.verifyEmail.mockResolvedValue(user);
            const result = await controller.verifyToken({ token: 'token' });
            expect(result.user).toEqual(user);
        });

        it('should throw BadRequestException if missing token', async () => {
            await expect(controller.verifyToken({ token: '' })).rejects.toThrow(BadRequestException);
        });

        it('should throw UnauthorizedException if token invalid', async () => {
            mockAuthService.verifyEmail.mockResolvedValue(null);
            await expect(controller.verifyToken({ token: 'invalid' })).rejects.toThrow(UnauthorizedException);
        });
    });

    describe('register', () => {
        const registerDto = {
            complete_name: 'Test',
            username: 'test',
            email: 'test@test.com',
            password: 'pass',
            role: UserRole.Volunteer,
        };

        it('should register successfully', async () => {
            await controller.register(registerDto);
            expect(service.register).toHaveBeenCalledWith(registerDto);
        });

        it('should throw BadRequestException if missing fields', async () => {
            await expect(controller.register({ ...registerDto, username: '' })).rejects.toThrow(BadRequestException);
        });
    });
});
