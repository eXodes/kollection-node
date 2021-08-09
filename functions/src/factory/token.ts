import { firestore } from "firebase-admin";
import { config } from "firebase-functions";
import jwt, { JwtPayload, VerifyErrors } from "jsonwebtoken";
import { AuthenticationError } from "./error";

export const ACCESS_TOKEN_MAX_AGE = 20;
export const REFRESH_TOKEN_MAX_AGE = 60 * 60 * 24 * 7;

const createAccessToken = (user: Partial<firestore.DocumentData>): string => {
  return jwt.sign(user, config().token.accessSecret, {
    expiresIn: ACCESS_TOKEN_MAX_AGE,
  });
};

const createRefreshToken = (user: Partial<firestore.DocumentData>): string => {
  return jwt.sign(user, config().token.refreshSecret);
};

const verifyAccessToken = (token: string): void => {
  jwt.verify(
    token,
    config().token.accessSecret,
    (error: VerifyErrors | null) => {
      if (error)
        throw new AuthenticationError(
          "auth/unauthenticated",
          "Not authenticated."
        );
    }
  );
};

const verifyRefreshToken = async (
  refreshToken: string
): Promise<JwtPayload> => {
  try {
    return (await jwt.verify(
      refreshToken,
      config().token.refreshSecret
    )) as JwtPayload;
  } catch (_) {
    throw new AuthenticationError("auth/unauthenticated", "Not authenticated.");
  }
};

export {
  createAccessToken,
  verifyAccessToken,
  createRefreshToken,
  verifyRefreshToken,
};
