import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserRole } from './users/user.schema';
import { UserService } from './users/user.service';
import * as bcrypt from 'bcrypt';
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

@Injectable()
export class AuthService {
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

  async register(registerDto: RegisterUserDTO): Promise<User> {
    // Verifica que el correo y el username no estén ya en uso
    const existingUser = await this.usersService.findByEmailOrUsername(
      registerDto.email,
      registerDto.username,
    );
    if (existingUser) {
      throw new BadRequestException('Email or Username already in use');
    }
    const pw = await this.hashPassword(registerDto.password);

    return await this.usersService.create(
      new User(
        registerDto.complete_name,
        registerDto.username,
        registerDto.email,
        pw,
        registerDto.profile_image,
        false,
        registerDto.role,
      ),
    );
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
    };
  }

  async forgotPassword(email: string) {
    const user = await this.usersService.findByEmailOrUsername(email, '');
    if (!user) {
      throw new BadRequestException('Email not found');
    }

    const resetToken = uuidv4();
    await this.usersService.saveResetToken(user.id, resetToken);

    const host =
      process.env.NODE_ENV === 'production'
        ? 'https://rayuela-frontend.vercel.app'
        : 'http://localhost:5173';
    const resetLink = `${host}/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: 'noreply@rayuela.com', // Dirección de correo del remitente
      to: email, // Dirección de correo del destinatario
      subject: 'Contraseña olvidada', // Asunto del correo
      text: `Parece que has olvidado tu contraseña! Puedes resetearla en este link ${resetLink} `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log('Correo enviado con éxito');
    } catch (error) {
      console.error('Error al enviar el correo:', error);
    }
  }

  async recoverPassword(token: string, newPassword: string) {
    const u = await this.usersService.getUserByResetToken(token);
    u.password = await this.hashPassword(newPassword);
    u.resetToken = null;
    return await this.usersService.update(u.id, u);
  }
}
