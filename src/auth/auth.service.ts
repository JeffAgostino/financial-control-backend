import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async register(data: RegisterDto) {
    const saltRounds = 10; // Pode ser movido para uma variável de ambiente
    const hashedPassword = await bcrypt.hash(data.password, saltRounds);

    return this.usersService.create({
      ...data,
      password: hashedPassword,
    });
  }

  async login(data: LoginDto) {
    const user = await this.usersService.findByEmail(data.email);

    if (!user) throw new NotFoundException('User not found');

    const isValid = await bcrypt.compare(data.password, user.password);

    if (!isValid) throw new UnauthorizedException('Invalid credentials');

    return { message: 'login ok (JWT virá depois)' };
  }
}