import { Router } from "express";
import { authentication } from "../../middleware/authentication";
import {
  verify,
  authenticate,
  clearToken,
  create,
  refreshToken,
} from "./auth.controller";

const authRoute = Router();

authRoute.get("", authentication, verify);
authRoute.post("/create", create);
authRoute.post("/authenticate", authenticate);
authRoute.post("/token", refreshToken);
authRoute.post("/clear", clearToken);

export { authRoute };
