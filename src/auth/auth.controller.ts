import {
  Body,
  Controller,
  Get,
  Post,
  Res,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SingUpDto } from './dtos/singUpDto';
import { LoginDto } from './dtos/loginDto';
import { AuthGuard } from './auth.guard';
import { RefreshTokenDto } from './dtos/RefreshTokenDto';
import { response, Response } from 'express';
import { JwtService } from '@nestjs/jwt';

// @UseGuards(AuthGuard)
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private jwtService: JwtService,
  ) {}

  //#signUp
  @Post('signUp')
  async singUp(@Body() signUpData: SingUpDto) {
    return this.authService.singUp(signUpData);
  }

  //#signIn
  @Post('signIn')
  async signIn(
    @Body() loginData: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const accessToken = (await this.authService.signIn(loginData)).accessToken;
    const refreshToken = (await this.authService.signIn(loginData))
      .refreshToken;
    response.status(200);
    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return {
      accessToken: accessToken,
    };
  }

  //#refresh
  @Post('refresh')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    const accessToken = (await this.authService.refreshTokens(refreshTokenDto.refreshToken)).accessToken;
    return {
      accessToken: accessToken
    }
  }

  //#logout
  @Post('logout')
  async logout(@Res({ passthrough: true }) response: Response) {
    response.status(200);
    response.clearCookie('refresh_token');
    return {
      message: 'successful logout',
    };
  }

  //#getUserById
  @UseGuards(AuthGuard)
  @Get('user')
  async getUserById(@Req() req) {
    return this.authService.getUserById(req.userId);
  }
}
