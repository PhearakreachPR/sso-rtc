import { IsEmail, IsStrongPassword, IsOptional, IsString, MinLength } from "class-validator";

export class createUserRequest {
    @IsEmail({}, { message: 'Please provide a valid email address' })
    email: string;
    
    @IsStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
    }, { 
        message: 'Password must be at least 8 characters long and contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 symbol' 
    })
    password: string;
    
    @IsOptional()
    @IsString({ message: 'First name must be a string' })
    @MinLength(1, { message: 'First name cannot be empty' })
    firstName?: string;
    
    @IsOptional()
    @IsString({ message: 'Last name must be a string' })
    @MinLength(1, { message: 'Last name cannot be empty' })
    lastName?: string;
}