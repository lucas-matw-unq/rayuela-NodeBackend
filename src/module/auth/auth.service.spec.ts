import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from './users/user.service';
import { JwtService } from '@nestjs/jwt';
import { BadRequestException } from '@nestjs/common';
import { User } from './users/user.entity';
import { UserRole } from './users/user.schema';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import { RegisterUserDTO } from './auth.controller';

// Mock de dependencias externas
jest.mock('bcrypt');
jest.mock('uuid');
jest.mock('nodemailer');

describe('AuthService', () => {
  let service: AuthService;

  const mockUserService = {
    findByEmailOrUsername: jest.fn(),
    create: jest.fn(),
    getUserByResetToken: jest.fn(),
    update: jest.fn(),
    saveResetToken: jest.fn(),
  };

  const mockJwtService = {
    sign: jest.fn(),
  };

  const mockTransporter = {
    sendMail: jest.fn(),
  };

  beforeEach(async () => {
    (nodemailer.createTransport as jest.Mock).mockReturnValue(mockTransporter);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UserService, useValue: mockUserService },
        { provide: JwtService, useValue: mockJwtService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateUser', () => {
    it('should return user if validation is successful', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.validateUser('testuser', 'password');
      expect(result).toEqual(user);
      expect(mockUserService.findByEmailOrUsername).toHaveBeenCalledWith(
        '',
        'testuser',
      );
      expect(bcrypt.compare).toHaveBeenCalledWith('password', 'hashedpassword');
    });

    it('should return null if user not found', async () => {
      mockUserService.findByEmailOrUsername.mockResolvedValue(null);
      const result = await service.validateUser('testuser', 'password');
      expect(result).toBeNull();
    });

    it('should return null if password does not match', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await service.validateUser('testuser', 'password');
      expect(result).toBeNull();
    });
  });

  describe('register', () => {
    const registerDto: RegisterUserDTO = {
      complete_name: 'Test User',
      username: 'testuser',
      email: 'test@test.com',
      password: 'password',
      profile_image: '',
      role: UserRole.Volunteer,
    };

    it('should register a new user and send verification email', async () => {
      mockUserService.findByEmailOrUsername.mockResolvedValue(null);
      (bcrypt.genSalt as jest.Mock).mockResolvedValue('salt');
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');
      (uuidv4 as jest.Mock).mockReturnValue('test-token');
      mockUserService.create.mockResolvedValue(null);
      await service.register(registerDto);

      expect(mockUserService.findByEmailOrUsername).toHaveBeenCalledWith(
        registerDto.email,
        registerDto.username,
      );
      expect(bcrypt.hash).toHaveBeenCalledWith('password', 'salt');
      expect(mockUserService.create).toHaveBeenCalled();
      expect(mockTransporter.sendMail).toHaveBeenCalled();
    });

    it('should throw BadRequestException if email or username is already in use', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      await expect(service.register(registerDto)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw BadRequestException if sending email fails', async () => {
      mockUserService.findByEmailOrUsername.mockResolvedValue(null);
      (bcrypt.genSalt as jest.Mock).mockResolvedValue('salt');
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');
      (uuidv4 as jest.Mock).mockReturnValue('test-token');
      mockUserService.create.mockResolvedValue(null);
      mockTransporter.sendMail.mockImplementationOnce(() => {
        throw new Error('Mail error');
      });

      await expect(service.register(registerDto)).rejects.toThrow(
        new BadRequestException('Error al enviar el correo de verificación'),
      );
    });
  });

  describe('verifyEmail', () => {
    it('should verify user email', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      user.resetToken = 'valid-token';
      user.verifyAccount = jest.fn();
      mockUserService.getUserByResetToken.mockResolvedValue(user);
      mockUserService.update.mockResolvedValue(user);

      const result = await service.verifyEmail('valid-token');

      expect(mockUserService.getUserByResetToken).toHaveBeenCalledWith(
        'valid-token',
      );
      expect(user.verifyAccount).toHaveBeenCalled();
      expect(result.resetToken).toBeNull();
      expect(mockUserService.update).toHaveBeenCalledWith(user.id, user);
    });

    it('should throw BadRequestException for invalid token', async () => {
      mockUserService.getUserByResetToken.mockResolvedValue(null);
      await expect(service.verifyEmail('invalid-token')).rejects.toThrow(
        new BadRequestException('Token inválido o expirado'),
      );
    });
  });

  describe('hashPassword', () => {
    it('should return a hashed password', async () => {
      (bcrypt.genSalt as jest.Mock).mockResolvedValue('salt');
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');

      const result = await service.hashPassword('password');
      expect(result).toBe('hashedpassword');
    });
  });

  describe('login', () => {
    it('should return an access token', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      user.id = 'user-id';
      mockJwtService.sign.mockReturnValue('test-token');

      const result = await service.login(user);

      expect(result).toEqual({ access_token: 'test-token' });
      expect(mockJwtService.sign).toHaveBeenCalledWith({
        username: user.username,
        sub: user.id,
        role: user.role,
      });
    });
  });

  describe('forgotPassword', () => {
    it('should send a password reset email', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      user.id = 'user-id';
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      (uuidv4 as jest.Mock).mockReturnValue('reset-token');

      await service.forgotPassword('test@test.com');

      expect(mockUserService.findByEmailOrUsername).toHaveBeenCalledWith(
        'test@test.com',
        '',
      );
      expect(mockUserService.saveResetToken).toHaveBeenCalledWith(
        'user-id',
        'reset-token',
      );
      expect(mockTransporter.sendMail).toHaveBeenCalled();
    });

    it('should throw BadRequestException if email not found', async () => {
      mockUserService.findByEmailOrUsername.mockResolvedValue(null);
      await expect(service.forgotPassword('test@test.com')).rejects.toThrow(
        new BadRequestException('Email not found'),
      );
    });

    it('should handle error when sending email', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      user.id = 'user-id';
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      (uuidv4 as jest.Mock).mockReturnValue('reset-token');
      mockTransporter.sendMail.mockImplementationOnce(() => {
        throw new Error('Mail error');
      });
      const consoleErrorSpy = jest
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      await service.forgotPassword('test@test.com');
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });

    it('should log success message', async () => {
      const user = new User('T', 'u', 'test@test.com', 'p');
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
      mockTransporter.sendMail.mockResolvedValueOnce(undefined);
      await service.forgotPassword('test@test.com');
      expect(logSpy).toHaveBeenCalledWith('Correo enviado con éxito');
      logSpy.mockRestore();
    });
  });

  describe('recoverPassword', () => {
    it('should recover user password', async () => {
      const user = new User(
        'Test',
        'testuser',
        'test@test.com',
        'oldpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      user.id = 'user-id';
      mockUserService.getUserByResetToken.mockResolvedValue(user);
      (bcrypt.genSalt as jest.Mock).mockResolvedValue('salt');
      (bcrypt.hash as jest.Mock).mockResolvedValue('newhashedpassword');
      mockUserService.update.mockResolvedValue({
        ...user,
        password: 'newhashedpassword',
        resetToken: null,
      });

      const result = await service.recoverPassword(
        'reset-token',
        'newpassword',
      );

      expect(mockUserService.getUserByResetToken).toHaveBeenCalledWith(
        'reset-token',
      );
      expect(bcrypt.hash).toHaveBeenCalledWith('newpassword', 'salt');
      expect(mockUserService.update).toHaveBeenCalledWith(
        'user-id',
        expect.any(User),
      );
      expect(result.password).toBe('newhashedpassword');
      expect(result.resetToken).toBeNull();
    });
  });
});
