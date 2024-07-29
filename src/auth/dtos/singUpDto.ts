import { IsEmail, IsString, Matches, MinLength } from "class-validator";

export class SingUpDto {

    @IsEmail()
    email: string;

    @IsString()
    password: string;

}