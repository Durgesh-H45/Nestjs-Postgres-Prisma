import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDTO } from './create-user-dto';
import { SignupResponse } from './user';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma.service';
import { LoginDTO } from './login-dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}
  async signup(payload: CreateUserDTO): Promise<SignupResponse> {
    const existingUser = await this.prisma.user.findFirst({
      where: {
        email: payload.email,
      },
    });
    if (existingUser) {
      throw new BadRequestException(
        'User created with the email you provided',
        {
          cause: new Error(),
          description: 'user is already registered',
        },
      );
    }
    const hash = await this.encryptPassword(payload.password, 10);
    payload.password = hash;
    return await this.prisma.user.create({
      data: payload,
      select: {
        email: true,
        id: true,
      },
    });
  }

  async login(loginDTO: LoginDTO): Promise<{ accessToken: string }> {
    // find user based on email
    const user = await this.prisma.user.findFirst({
      where: {
        email: loginDTO.email,
      },
    });
    // if there is no user we can unauthorized
    if (!user) {
      throw new UnauthorizedException();
    }
    // decrypt the user password
    const isMatched = await this.decryptPassword(
      loginDTO.password,
      user.password,
    );
    if (!isMatched) {
      throw new UnauthorizedException('Invalid password');
    }
    // match the user provided password with decrypted
    // if password not matched then send the error invalid password
    const accessToken = await this.jwtService.signAsync(
      {
        email: user.email,
        id: user.id,
        role: user.role,
      },
      { expiresIn: '1d' },
    );
    // return json web token
    return { accessToken };
  }

  async findAll() {
    return this.prisma.user.findMany({
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        blocked: true,
        role: true,
        createdAt: true,
      },
      orderBy: { id: 'asc' },
    });
  }

  async remove(id: number) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with id ${id} was not found`);
    }

    await this.prisma.user.delete({ where: { id } });
  }

  async encryptPassword(plainText, saltRounds) {
    return await bcrypt.hash(plainText, saltRounds);
  }
  async decryptPassword(plainText, hash) {
    return await bcrypt.compare(plainText, hash);
  }
}
