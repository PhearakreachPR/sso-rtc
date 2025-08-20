import { IsEmail, IsStrongPassword } from "class-validator";

export class createUserRequest {
    @IsEmail()
    email: string;
    @IsStrongPassword()
    password : string;
}
    
