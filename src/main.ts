// src/main.ts - Updated to serve PHP-like routes
import { NestFactory } from "@nestjs/core";
import { NestExpressApplication } from "@nestjs/platform-express";
import { AppModule } from "./app.module";
import { ValidationPipe } from "@nestjs/common";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import { join } from "path";
import * as bodyParser from 'body-parser';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));
  // Views for SSO pages (if you want to use templates)
  app.setBaseViewsDir(join(__dirname, "..", "views"));
  app.setViewEngine("hbs");

  
  // CORS configuration
  app.enableCors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        "http://localhost:3000",
        "http://localhost:8000", 
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
        "https://rtc-bb.camai.kh",
        "http://localhost:6000",
        "http://localhost:5000"
      ];
      
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        console.log('Blocked by CORS:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: [
      'Origin', 
      'X-Requested-With', 
      'Content-Type', 
      'Accept', 
      'Authorization',
      'X-API-Key'
    ],
  });

  // Global validation
  app.useGlobalPipes(new ValidationPipe({ 
    whitelist: true, 
    forbidNonWhitelisted: true, 
    transform: true 
  }));

  // Cookie parser
  app.use(cookieParser(process.env.COOKIE_SECRET || "your-secret-key"));

  // Trust proxy if production
  if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
  }

  // MongoDB connection
  try {
    await mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/sso-backend");
    console.log("✅ Connected to MongoDB!");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  }

  const port = process.env.PORT || 3000;
  await app.listen(port);

  console.log(`🚀 SSO Server running on: http://localhost:${port}`);
  console.log(`🔐 Available endpoints:`);
  console.log(`   - GET  http://localhost:${port}/auth/login`);
  console.log(`   - POST http://localhost:${port}/auth/login`);
  console.log(`   - GET  http://localhost:${port}/auth/verify-token`);
  console.log(`   - GET  http://localhost:${port}/auth/user-info`);
}
bootstrap().catch(err => {
  console.error("🛑 Bootstrap failed:", err);
  process.exit(1);
});