import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SingUpDto } from './dtos/singUpDto';
import { LoginDto } from './dtos/loginDto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async singUp(@Body() signUpData: SingUpDto) {
    return this.authService.singUp(signUpData);
  }

  @Post('login')
  async login(
    @Body() loginData: LoginDto,
    @Res({passthrough: true}) response: Response
  ) {
    const access_token = await this.authService.login(loginData);
    response.cookie('access_token', access_token, {httpOnly: true})
    return {
      message: 'login successful'
    }
  }
  
}
