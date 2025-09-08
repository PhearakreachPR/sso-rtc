import { NestFactory } from "@nestjs/core";
import { NestExpressApplication } from "@nestjs/platform-express";
import { AppModule } from "./app.module";
import { ValidationPipe } from "@nestjs/common";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import { join } from "path";

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // Views for SSO pages
  app.setBaseViewsDir(join(__dirname, "..", "views"));
  app.setViewEngine("hbs");

  // Global validation
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));

  // Cookie parser
  app.use(cookieParser(process.env.COOKIE_SECRET || "your-secret-key"));

  // CORS
  app.enableCors({
    origin: [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://127.0.0.1:5500",
      "http://127.0.0.1:5501",
      "http://localhost:60000",
      "http://localhost:5000"
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
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
