import { NestFactory } from "@nestjs/core"
import { NestExpressApplication } from "@nestjs/platform-express"
import { AppModule } from "./app.module"
import { ValidationPipe } from "@nestjs/common"
import cookieParser from "cookie-parser"
import mongoose from "mongoose"
import { join } from "path"

async function bootstrap() {
  await mongoose.connect("mongodb://localhost:27017/sso-backend")

  const app = await NestFactory.create<NestExpressApplication>(AppModule)

  //  Added handlebars view engine for SSO login page
  app.setBaseViewsDir(join(__dirname, "..", "views"))
  app.setViewEngine("hbs")

  app.useGlobalPipes(new ValidationPipe())
  app.use(cookieParser())

  app.enableCors({
    origin: "http://localhost:3001",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })

  mongoose.connection.once('open', () => {
    console.log('✅ Connected to MongoDB!')
  })
  
  mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err)
  })

  await app.listen(process.env.PORT ?? 3000)
}

bootstrap()
