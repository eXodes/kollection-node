import express from "express";
import { AuthenticationError } from "../factory/error";
import { verifyAccessToken } from "../factory/token";

const authentication = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void | express.Response> => {
  try {
    const authorization = req.headers["authorization"] as string | null;
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
