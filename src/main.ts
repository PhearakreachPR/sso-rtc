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

  // Global validation
  app.useGlobalPipes(new ValidationPipe({ 
    whitelist: true, 
    forbidNonWhitelisted: true, 
    transform: true 
  }));

  // Cookie parser
  app.use(cookieParser(process.env.COOKIE_SECRET || "your-secret-key"));

  // CORS - Enable for all origins to mimic PHP behavior
  app.enableCors({
  origin: [
    "http://localhost:3000",
    "http://localhost:3001", 
    "http://localhost:5000",
    "http://localhost:60000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:5000", 
    "http://127.0.0.1:60000",
    "http://localhost"
  ],
  credentials: true, // ← This is crucial!
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
});
  // Add middleware to handle PHP-like behavior
  app.use((req, res, next) => {
    // Set headers similar to PHP
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    // Handle PHP-like session behavior
    if (!req.session) {
      req.session = {};
    }
    
    next();
  });

  // MongoDB connection
  try {
    await mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/sso-backend");
    console.log("✅ Connected to MongoDB!");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  }

  // Trust proxy if production
  if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
  }

  const port = process.env.PORT || 3000;
  await app.listen(port);

  console.log(`🚀 Server running on http://localhost:${port}`);
}
bootstrap().catch(err => {
  console.error("🛑 Bootstrap failed:", err);
  process.exit(1);
});