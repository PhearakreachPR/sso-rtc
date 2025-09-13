import { Controller, Get, Query, Res } from '@nestjs/common';
import { AppService } from './app.service';
import type { Response } from 'express';
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
  @Get("login.php")
  redirectLoginPhp(@Query() query: any, @Res() res: Response) {
    const queryString = new URLSearchParams(query).toString();
    return res.redirect(`/auth/php-login?${queryString}`);
  }

  @Get("logout.php") 
  redirectLogoutPhp(@Query() query: any, @Res() res: Response) {
    const queryString = new URLSearchParams(query).toString();
    return res.redirect(`/auth/php-logout?${queryString}`);
  }
}
