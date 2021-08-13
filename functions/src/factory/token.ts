import { firestore } from "firebase-admin";
import { Response } from "express";

import { JwtPayload, sign, verify, VerifyErrors } from "jsonwebtoken";
import { AuthPayload, RefreshPayload } from "../feature/auth/auth.types";
import { AuthenticationError } from "./error";
import {
  ACCESS_SECRET,
  ACCESS_TOKEN_MAX_AGE,
  REFRESH_SECRET,
  REFRESH_TOKEN_MAX_AGE,
} from "../config";

const dev = process.env.NODE_ENV === "development";

const createAccessToken = (user: Partial<firestore.DocumentData>): string => {
  return sign(user, ACCESS_SECRET, {
    expiresIn: ACCESS_TOKEN_MAX_AGE,
  });
};

const decodeAccessToken = (token: string): AuthPayload => {
  let data: AuthPayload;

  verify(
    token,
    ACCESS_SECRET,
    (error: VerifyErrors | null, payload: JwtPayload | undefined) => {
      if (error) {
        throw new AuthenticationError(
          "auth/unauthenticated",
          "Not authenticated."
        );
      }

      if (!payload)
        throw new AuthenticationError(
          "auth/unauthenticated",
          "Not authenticated."
        );

      data = payload as AuthPayload;
    }
  );

  return data!;
};

const verifyAccessToken = (token: string): void => {
  verify(token, ACCESS_SECRET, (error: VerifyErrors | null) => {
    if (error?.name === "TokenExpiredError")
      throw new AuthenticationError(
        "auth/expired",
        "Authorization token expired."
      );
    else if (error)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );
  });
};

const createRefreshToken = (payload: RefreshPayload): string => {
  return sign(payload, REFRESH_SECRET, {
    // TODO: Can be added if needed to revoke the token manually
    // expiresIn: REFRESH_TOKEN_MAX_AGE,
  });
};

const decodeRefreshToken = (refreshToken: string): RefreshPayload => {
  let data: RefreshPayload;

  verify(
    refreshToken,
    REFRESH_SECRET,
    (error: VerifyErrors | null, payload: JwtPayload | undefined) => {
      if (error)
        throw new AuthenticationError(
          "auth/unauthenticated",
          "Not authenticated."
        );

      if (!payload)
        throw new AuthenticationError(
          "auth/unauthenticated",
          "Not authenticated."
        );

      data = payload as RefreshPayload;
    }
  );

  return data!;
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
  decodeRefreshToken,
  sendRefreshToken,
};
