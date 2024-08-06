import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SingUpDto } from './dtos/singUpDto';
import { LoginDto } from './dtos/loginDto';
import { AuthGuard } from './auth.guard';
import { User } from './schemas/user.schema';
import { RefreshTokenDto } from './dtos/RefreshTokenDto';
// import { Response } from 'express';

// @UseGuards(AuthGuard)
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  //#signUp
  @Post('signUp')
  async singUp(@Body() signUpData: SingUpDto) {
    return this.authService.singUp(signUpData);
  }

  //#signIn
  @Post('signIn')
  async signIn(
    @Body() loginData: LoginDto,
    // @Res({passthrough: true}) response: Response
  ) {
    return this.authService.signIn(loginData);
    // response.cookie('access_token', access_token, {httpOnly: true})
    // return {
    //   message: 'login successful'
    // }
  }

  //#refresh 
  @Post('refresh')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto.refreshToken);
  }


  //#getUserById
  @UseGuards(AuthGuard)
  @Get('user')
  async getUserById(@Req() req){
    return this.authService.getUserById(req.userId);
  }
}
