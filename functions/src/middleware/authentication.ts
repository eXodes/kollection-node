import { Request, Response, NextFunction } from "express";
import { AuthenticationError } from "../factory/error";
import { verifyAccessToken } from "../factory/token";

const authentication = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void | Response> => {
  try {
    const authorization = req.headers["authorization"];
    const type = authorization?.split(" ")[0];
    const credentials = authorization?.split(" ")[1];

    if (!authorization || type !== "Bearer" || !credentials)
      throw new AuthenticationError("auth/unauthorized", "Not authorized.");

    verifyAccessToken(credentials);

    next();
  } catch (error) {
    return res.status(401).send(error);
  }
};

export { authentication };
