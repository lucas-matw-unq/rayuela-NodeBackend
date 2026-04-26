import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from './users/user.service';
import { JwtService } from '@nestjs/jwt';
import { BadRequestException } from '@nestjs/common';
import { User } from './users/user.entity';
import { UserRole } from './users/user.schema';
import * as bcrypt from 'bcryptjs';
import * as nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import { RegisterUserDTO } from './auth.controller';

// Mock de dependencias externas
jest.mock('bcryptjs');
jest.mock('uuid');
jest.mock('nodemailer');
jest.mock('@nestjs/jwt', () => ({
  JwtService: class JwtService {},
}));

describe('AuthService', () => {
  let service: AuthService;

  const mockUserService = {
    findByEmailOrUsername: jest.fn(),
    findByGoogleId: jest.fn(),
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
    process.env.GOOGLE_CLIENT_ID = 'google-client-id';
    global.fetch = jest.fn();

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
      mockTransporter.sendMail.mockRejectedValueOnce(new Error('SMTP auth error'));

      await expect(service.register(registerDto)).rejects.toThrow(
        new BadRequestException('Error al enviar el correo de verificación'),
      );
    });

    it('should propagate sendMail rejection — not swallow it silently', async () => {
      mockUserService.findByEmailOrUsername.mockResolvedValue(null);
      (bcrypt.genSalt as jest.Mock).mockResolvedValue('salt');
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');
      (uuidv4 as jest.Mock).mockReturnValue('test-token');
      mockUserService.create.mockResolvedValue(null);
      mockTransporter.sendMail.mockRejectedValueOnce(new Error('SMTP auth error'));

      const loggerErrorSpy = jest.spyOn(service['logger'], 'error');

      await expect(service.register(registerDto)).rejects.toThrow(BadRequestException);
      expect(loggerErrorSpy).toHaveBeenCalled();
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

      expect(result).toEqual({
        access_token: 'test-token',
        username: 'testuser',
      });
      expect(mockJwtService.sign).toHaveBeenCalledWith({
        username: user.username,
        sub: user.id,
        role: user.role,
      });
    });
  });

  describe('authenticateWithGoogle', () => {
    const googlePayload = {
      sub: 'google-123',
      email: 'google@test.com',
      email_verified: true,
      name: 'Google User',
      picture: 'https://example.com/avatar.png',
    };

    it('should link an existing email account and return a session', async () => {
      const user = new User(
        'Test',
        'testuser',
        'google@test.com',
        'hashedpassword',
        '',
        false,
        UserRole.Volunteer,
      );
      user.id = 'user-id';
      mockUserService.findByGoogleId.mockResolvedValue(null);
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      mockUserService.update.mockImplementation(async (_id, updatedUser) => updatedUser);
      mockJwtService.sign.mockReturnValue('google-token');
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          ...googlePayload,
          aud: 'google-client-id',
        }),
      });

      const result = await service.authenticateWithGoogle('credential');

      expect(mockUserService.findByGoogleId).toHaveBeenCalledWith('google-123');
      expect(mockUserService.update).toHaveBeenCalledWith('user-id', user);
      expect(user.googleId).toBe('google-123');
      expect(user.verified).toBe(true);
      expect(result).toEqual({
        access_token: 'google-token',
        username: 'testuser',
        isNewUser: false,
      });
    });

    it('should create a verified user when the Google account is new and a username is provided', async () => {
      mockUserService.findByGoogleId.mockResolvedValue(null);
      mockUserService.findByEmailOrUsername
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);
      mockUserService.create.mockImplementation(async (user) => {
        user.id = 'new-user-id';
        return user;
      });
      mockJwtService.sign.mockReturnValue('google-token');
      (bcrypt.genSalt as jest.Mock).mockResolvedValue('salt');
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');
      (uuidv4 as jest.Mock).mockReturnValue('generated-secret');
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          ...googlePayload,
          aud: 'google-client-id',
        }),
      });

      const result = await service.authenticateWithGoogle(
        'credential',
        'google_user',
      );

      expect(mockUserService.create).toHaveBeenCalled();
      expect(result).toEqual({
        access_token: 'google-token',
        username: 'google_user',
        isNewUser: true,
      });
    });

    it('should request a username for a new Google signup when none is provided', async () => {
      mockUserService.findByGoogleId.mockResolvedValue(null);
      mockUserService.findByEmailOrUsername
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          ...googlePayload,
          aud: 'google-client-id',
        }),
      });

      await expect(service.authenticateWithGoogle('credential')).rejects.toMatchObject({
        response: {
          message: 'Username is required for new Google signup',
          requiresUsername: true,
          suggestedUsername: 'google_user',
        },
      });
    });

    it('should create a verified user with the requested username', async () => {
      mockUserService.findByGoogleId.mockResolvedValue(null);
      mockUserService.findByEmailOrUsername
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);
      mockUserService.create.mockImplementation(async (user) => {
        user.id = 'new-user-id';
        return user;
      });
      mockJwtService.sign.mockReturnValue('google-token');
      (bcrypt.genSalt as jest.Mock).mockResolvedValue('salt');
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');
      (uuidv4 as jest.Mock).mockReturnValue('generated-secret');
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          ...googlePayload,
          aud: 'google-client-id',
        }),
      });

      const result = await service.authenticateWithGoogle(
        'credential',
        'chosen-user',
      );

      expect(mockUserService.create).toHaveBeenCalledWith(
        expect.objectContaining({
          username: 'chosen-user',
        }),
      );
      expect(result).toEqual({
        access_token: 'google-token',
        username: 'chosen-user',
        isNewUser: true,
      });
    });

    it('should reject requested usernames already in use for a new Google user', async () => {
      mockUserService.findByGoogleId.mockResolvedValue(null);
      mockUserService.findByEmailOrUsername
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(new User('Taken', 'taken-user', 'taken@test.com', 'password'));
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          ...googlePayload,
          aud: 'google-client-id',
        }),
      });

      await expect(
        service.authenticateWithGoogle('credential', 'taken-user'),
      ).rejects.toThrow('Username already in use');
    });

    it('should reject invalid Google credentials', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
      });

      await expect(service.authenticateWithGoogle('credential')).rejects.toThrow(
        'Invalid Google credentials',
      );
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

    it('should not throw when sending email fails — logs error and continues', async () => {
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
      mockTransporter.sendMail.mockRejectedValueOnce(new Error('SMTP auth error'));

      const loggerErrorSpy = jest.spyOn(service['logger'], 'error');

      await expect(service.forgotPassword('test@test.com')).resolves.toBeUndefined();
      expect(loggerErrorSpy).toHaveBeenCalled();
    });

    it('should log success when email is sent', async () => {
      const user = new User('T', 'u', 'test@test.com', 'p');
      user.id = 'user-id';
      mockUserService.findByEmailOrUsername.mockResolvedValue(user);
      mockTransporter.sendMail.mockResolvedValueOnce(undefined);

      const loggerLogSpy = jest.spyOn(service['logger'], 'log');

      await service.forgotPassword('test@test.com');
      expect(loggerLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('test@test.com'),
      );
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
