import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import e from "express";
import passport from "passport";

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
    
}
