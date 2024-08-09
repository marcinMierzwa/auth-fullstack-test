import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { SingUpDto } from './dtos/singUpDto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/loginDto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';

// uuidv4(); // ⇨ '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
  ) {}

  //#signUp
  async singUp(signUpData: SingUpDto) {
    const { email, password } = signUpData;
    const hashedPassword = await bcrypt.hash(password, 10);

    const emailInUse = await this.userModel.findOne({
      email: signUpData.email,
    });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
     const user = await this.userModel.create({
      email,
      password: hashedPassword
    });

    return {
      email: user.email,
      _id: user.id
    }
  }

    //#signIn
  async signIn(loginData: LoginDto) {
    const { email, password } = loginData;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('invalid credentials');
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new BadRequestException('invalid credentials');
    }
    return this.generateUserTokens(user._id);
  }

  //#refreshToken

  async generateUserTokens(userId) {
    const accessToken = await this.jwtService.signAsync({ userId }, {expiresIn: '20s'});
    const refreshToken = await this.jwtService.signAsync({ userId });

    await this.storeRefreshToken(refreshToken, userId);


    return {
     accessToken: accessToken,
     refreshToken: refreshToken
  }
}

async storeRefreshToken(refreshToken: string, userId: string) {
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + 7);
  await this.refreshTokenModel.updateOne({userId},{ $set: {expiryDate, refreshToken}}, {upsert:true});
}


async refreshTokens(refreshToken: string) {
  const token = await this.refreshTokenModel.findOne({
    refreshToken: refreshToken,
    expiryDate: { $gte: new Date()},
  });
  if (!token) {
    throw new UnauthorizedException('invalid refresh token');
  }
  return this.generateUserTokens(token.userId);
}


//#getUsers
async getUserById(userId: string) {
  const user = await this.userModel.findById(userId);
  return {
    _id: user._id,
    email: user.email,
  }
}
}
