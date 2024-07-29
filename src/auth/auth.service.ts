import {
  BadRequestException,
  Injectable,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { SingUpDto } from './dtos/singUpDto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/loginDto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async singUp(signUpData: SingUpDto) {
    const { email, password } = signUpData;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      return await this.userModel.create({
        email,
        password: hashedPassword,
      });
    } catch {
      return new BadRequestException('email has already exist');
    }
  }

  async login(loginData: LoginDto) {
    const { email, password } = loginData;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('invalid credentials');
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('invalid credentials');
    }
    return this.generateUserTokens(user._id);
  }

  async generateUserTokens(userId) {
    const access_token = this.jwtService.signAsync({ userId });
    return access_token;
  }
}
