import { firestore } from "firebase-admin";
import { config } from "firebase-functions";
import { Response } from "express";

import { JwtPayload, sign, verify, VerifyErrors } from "jsonwebtoken";
import { AuthPayload } from "../feature/auth/auth.types";
import { AuthenticationError } from "./error";

export const ACCESS_TOKEN_MAX_AGE = 60 * 5;
export const REFRESH_TOKEN_MAX_AGE = 60 * 60 * 24 * 7;
const dev = process.env.NODE_ENV === "development";

const createAccessToken = (user: Partial<firestore.DocumentData>): string => {
  return sign(user, config().token.accessSecret, {
    expiresIn: ACCESS_TOKEN_MAX_AGE,
  });
};

const createRefreshToken = (user: Partial<firestore.DocumentData>): string => {
  return sign(user, config().token.refreshSecret, {
    expiresIn: REFRESH_TOKEN_MAX_AGE,
  });
};

const decodeAccessToken = (token: string): AuthPayload => {
  return verify(token, config().token.accessSecret) as AuthPayload;
};

const verifyAccessToken = (token: string): void => {
  verify(token, config().token.accessSecret, (error: VerifyErrors | null) => {
    if (error)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );
  });
};

const verifyRefreshToken = async (
  refreshToken: string
): Promise<JwtPayload> => {
  try {
    return (await verify(
      refreshToken,
      config().token.refreshSecret
    )) as JwtPayload;
  } catch (_) {
    throw new AuthenticationError("auth/unauthenticated", "Not authenticated.");
  }
};

const sendRefreshToken = (res: Response, refreshToken: string): void => {
  res.cookie("jwt", refreshToken, {
    maxAge: 1000 * REFRESH_TOKEN_MAX_AGE,
    httpOnly: true,
    secure: !dev,
  });
};

export {
  createAccessToken,
  verifyAccessToken,
  decodeAccessToken,
  createRefreshToken,
  verifyRefreshToken,
  sendRefreshToken,
};
