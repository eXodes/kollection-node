import { Router } from "express";
import { authentication } from "../../middleware/authentication";
import {
  verify,
  authenticate,
  clearToken,
  create,
  revalidateToken,
} from "./auth.controller";

const authRoute = Router();

authRoute.get("", authentication, verify);
authRoute.post("/create", create);
authRoute.post("/authenticate", authenticate);
authRoute.post("/token", revalidateToken);
authRoute.post("/clear", clearToken);

export { authRoute };
