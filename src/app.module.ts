import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule, ConfigService } from '@nestjs/config';
import config from './config/config';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: [config],
    }),
    JwtModule.registerAsync({
      imports:[ConfigModule],
      useFactory: async (config) => ({
        secret: config.get('jwt.secret'),
        signOptions: {expiresIn: '1w'},
      }),
      global:true,
      inject: [ConfigService],
    }),
    MongooseModule.forRootAsync({
      imports:[ConfigModule],
      useFactory: async (config) => ({
        uri: config.get('database.connnectionString')
      }),
      inject: [ConfigService]
    }), 
    AuthModule
   ],
  controllers: [],
  providers: [],
})
export class AppModule {
  
}
