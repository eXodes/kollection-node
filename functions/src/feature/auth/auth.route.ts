import { Router } from "express";
import {
  authenticate,
  clearToken,
  verifyAccess,
  create,
  createToken,
} from "./auth.controller";

const authRoute = Router();

authRoute.post("/create", create);
authRoute.post("/authenticate", authenticate);
authRoute.post("/verify", verifyAccess);
authRoute.post("/token", createToken);
authRoute.post("/clear", clearToken);

export { authRoute };
