import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { get } from "http";

const getCurrentUserByContext = (context: ExecutionContext) => 
    context.switchToHttp().getRequest().user;

export const CurrentUser = createParamDecorator(
    (_data: unknown, context:ExecutionContext)=> 
        getCurrentUserByContext(context)
)  