import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserRole } from './users/user.schema';
import { UserService } from './users/user.service';
import * as bcrypt from 'bcryptjs';
import { User } from './users/user.entity';
import { RegisterUserDTO } from './auth.controller';
import { v4 as uuidv4 } from 'uuid';
import * as nodemailer from 'nodemailer';
import * as process from 'node:process';

export interface UserJWT {
  userId: string;
  username: string;
  role: UserRole;
}

interface GoogleTokenPayload {
  aud: string;
  email: string;
  email_verified: boolean | string;
  name?: string;
  picture?: string;
  sub: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private transporter;

  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
  ) {
    // Configura el transportador de nodemailer
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.NOREPLY_EMAIL,
        pass: process.env.NOREPLY_PW,
      },
    });
  }

  async validateUser(username: string, password: string): Promise<User> {
    const user = await this.usersService.findByEmailOrUsername('', username);
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    return null;
  }

  async register(registerDto: RegisterUserDTO): Promise<void> {
    // Verifica que el correo y el username no estén ya en uso
    const existingUser = await this.usersService.findByEmailOrUsername(
      registerDto.email,
      registerDto.username,
    );
    if (existingUser) {
      throw new BadRequestException('Email or Username already in use');
    }
    const pw = await this.hashPassword(registerDto.password);

    // Genera un token de verificación
    const verificationToken = uuidv4();

    // Crea el usuario con el token de verificación
    const newUser = new User(
      registerDto.complete_name,
      registerDto.username,
      registerDto.email,
      pw,
      registerDto.profile_image,
      false, // Usuario no verificado
      registerDto.role,
    );
    newUser.resetToken = verificationToken;

    await this.usersService.create(newUser);

    await this.sendVerificationEmail(verificationToken, registerDto);
  }

  async authenticateWithGoogle(credential: string, username?: string) {
    const googleUser = await this.verifyGoogleToken(credential);
    let user = await this.usersService.findByGoogleId(googleUser.sub);
    let isNewUser = false;

    if (!user) {
      user = await this.usersService.findByEmailOrUsername(googleUser.email, '');
    }

    if (user) {
      let shouldUpdate = false;

      if (user.googleId !== googleUser.sub) {
        user.googleId = googleUser.sub;
        shouldUpdate = true;
      }

      if (!user.verified) {
        user.verified = true;
        shouldUpdate = true;
      }

      if (!user.profileImage && googleUser.picture) {
        user.profileImage = googleUser.picture;
        shouldUpdate = true;
      }

      if (shouldUpdate) {
        user = await this.usersService.update(user.id, user);
      }
    } else {
      if (!username?.trim()) {
        throw new BadRequestException({
          message: 'Username is required for new Google signup',
          requiresUsername: true,
          suggestedUsername: await this.generateAvailableUsername(
            googleUser.email,
            googleUser.name,
          ),
        });
      }

      const selectedUsername = await this.resolveGoogleSignupUsername(
        username,
        googleUser.email,
        googleUser.name,
      );
      const generatedPassword = await this.hashPassword(uuidv4());
      const newUser = new User(
        googleUser.name || selectedUsername,
        selectedUsername,
        googleUser.email,
        generatedPassword,
        googleUser.picture || null,
        true,
        UserRole.Volunteer,
        undefined,
        [],
        [],
        [],
        [],
        googleUser.sub,
      );

      user = await this.usersService.create(newUser);
      isNewUser = true;
    }

    return {
      ...(await this.login(user)),
      isNewUser,
    };
  }

  async verifyEmail(token: string): Promise<User> {
    const user = await this.usersService.getUserByResetToken(token);
    if (!user) {
      throw new BadRequestException('Token inválido o expirado');
    }
    user.verifyAccount();
    user.resetToken = null;
    return await this.usersService.update(user.id, user);
  }

  private async sendVerificationEmail(
    verificationToken: string | Uint8Array,
    registerDto: RegisterUserDTO,
  ) {
    // Envía el correo de verificación
    const host = process.env.FRONTEND_URL;
    const verificationLink = `${host}/verify-email?token=${verificationToken}`;
    const mailOptions = {
      from: 'noreply@rayuela.com',
      to: registerDto.email,
      subject: 'Verificación de correo',
      text: `Por favor, verifica tu correo haciendo clic en el siguiente enlace: ${verificationLink}`,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Verification email sent to ${registerDto.email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send verification email to ${registerDto.email}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new BadRequestException(
        'Error al enviar el correo de verificación',
      );
    }
  }

  async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(password, salt);
  }

  async login(user: User) {
    const payload = {
      username: user.username,
      sub: user.id,
      role: user.role,
    };
    return {
      access_token: this.jwtService.sign(payload),
      username: user.username,
    };
  }

  async forgotPassword(email: string) {
    const user = await this.usersService.findByEmailOrUsername(email, '');
    if (!user) {
      throw new BadRequestException('Email not found');
    }

    const resetToken = uuidv4();
    await this.usersService.saveResetToken(user.id, resetToken);

    const host = process.env.FRONTEND_URL;

    const resetLink = `${host}/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: 'noreply@rayuela.com', // Dirección de correo del remitente
      to: email, // Dirección de correo del destinatario
      subject: 'Contraseña olvidada', // Asunto del correo
      text: `Parece que has olvidado tu contraseña! Puedes resetearla en este link ${resetLink} `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Password reset email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset email to ${email}`,
        error instanceof Error ? error.stack : String(error),
      );
    }
  }

  async recoverPassword(token: string, newPassword: string) {
    const u = await this.usersService.getUserByResetToken(token);
    u.password = await this.hashPassword(newPassword);
    u.resetToken = null;
    return await this.usersService.update(u.id, u);
  }

  private async verifyGoogleToken(
    credential: string,
  ): Promise<GoogleTokenPayload> {
    if (!process.env.GOOGLE_CLIENT_ID) {
      throw new BadRequestException('Google login is not configured');
    }

    try {
      const response = await fetch(
        `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`,
      );

      if (!response.ok) {
        throw new UnauthorizedException('Invalid Google credentials');
      }

      const payload = (await response.json()) as GoogleTokenPayload;

      if (!payload?.sub || !payload.email) {
        throw new UnauthorizedException('Invalid Google credentials');
      }

      if (payload.aud !== process.env.GOOGLE_CLIENT_ID) {
        throw new UnauthorizedException('Invalid Google credentials');
      }

      if (`${payload.email_verified}` !== 'true') {
        throw new UnauthorizedException('Google email is not verified');
      }

      return payload;
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
      }

      this.logger.warn(
        `Google authentication failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw new UnauthorizedException('Invalid Google credentials');
    }
  }

  private async generateAvailableUsername(email: string, name?: string | null) {
    const baseUsername =
      this.normalizeUsernameSeed(name) ||
      this.normalizeUsernameSeed(email.split('@')[0]) ||
      'rayuela_user';

    let candidate = baseUsername;
    let suffix = 1;

    while (await this.usersService.findByEmailOrUsername('', candidate)) {
      const suffixLabel = `_${suffix}`;
      candidate = `${baseUsername.slice(0, 30 - suffixLabel.length)}${suffixLabel}`;
      suffix += 1;
    }

    return candidate;
  }

  private async resolveGoogleSignupUsername(
    requestedUsername: string | undefined,
    email: string,
    name?: string | null,
  ) {
    const normalizedRequestedUsername = requestedUsername?.trim();

    if (normalizedRequestedUsername) {
      const existingUser = await this.usersService.findByEmailOrUsername(
        '',
        normalizedRequestedUsername,
      );

      if (existingUser) {
        throw new BadRequestException('Username already in use');
      }

      return normalizedRequestedUsername;
    }

    return this.generateAvailableUsername(email, name);
  }

  private normalizeUsernameSeed(seed?: string | null) {
    return (seed || '')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '_')
      .replace(/^[_\-.]+|[_\-.]+$/g, '')
      .slice(0, 30);
  }
}
