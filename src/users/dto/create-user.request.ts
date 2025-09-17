import { IsEmail, IsOptional, IsString, MinLength } from "class-validator";

export class createUserRequest {
    @IsEmail({}, { message: 'Please provide a valid email address' })
    email: string;
    
    @IsString({ message: 'Password must be a string' })
    @MinLength(6, { message: 'Password must be at least 6 characters long' })
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
