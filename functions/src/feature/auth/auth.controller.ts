import express from "express";
import { AuthenticationError } from "../../factory/error";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
  decodeAccessToken,
  REFRESH_TOKEN_MAX_AGE,
} from "../../factory/token";
import { validate } from "../../factory/validator";
import { AuthService } from "./auth.service";

const dev = process.env.NODE_ENV === "development";

const create = async (
  req: express.Request,
  res: express.Response
): Promise<express.Response> => {
  try {
    validate(req.body);

    const user = await AuthService.create(req.body);

    const token = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    await AuthService.saveToken(req.body.username, refreshToken);

    res.cookie("jwt", refreshToken, {
      maxAge: 1000 * REFRESH_TOKEN_MAX_AGE,
      httpOnly: true,
      secure: !dev,
    });

    return res.status(201).send({
      code: "auth/created",
      message: "User created.",
      token: token,
    });
  } catch (error) {
    return res.status(400).send(error);
  }
};

const authenticate = async (
  req: express.Request,
  res: express.Response
): Promise<express.Response> => {
  try {
    validate(req.body);

    const user = await AuthService.authenticate(req.body);

    const token = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    await AuthService.saveToken(req.body.username, refreshToken);

    res.cookie("jwt", refreshToken, {
      maxAge: 1000 * REFRESH_TOKEN_MAX_AGE,
      httpOnly: true,
      secure: !dev,
    });

    return res.status(200).send({
      code: "auth/authenticated",
      message: "User logged in.",
      token: token,
    });
  } catch (error) {
    return res.status(400).send(error);
  }
};

const verifyAccess = async (
  req: express.Request,
  res: express.Response
): Promise<express.Response> => {
  const accessToken = req.body.token;

  try {
    const payload = await decodeAccessToken(accessToken);

    return res.send({
      data: payload,
    });
  } catch (error) {
    return res.status(401).send(error);
  }
};

const createToken = async (
  req: express.Request,
  res: express.Response
): Promise<express.Response> => {
  const refreshToken = req.cookies.jwt;

  try {
    if (!refreshToken)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    const valid = await AuthService.getToken(refreshToken);

    if (!valid)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    const payload = await verifyRefreshToken(refreshToken);

    const token = createAccessToken({
      id: payload?.id,
      name: payload?.name,
      email: payload?.email,
    });

    return res.status(201).send({
      code: "auth/authorized",
      message: "Token created.",
      token,
    });
  } catch (error) {
    return res.status(401).send(error);
  }
};

const clearToken = async (
  req: express.Request,
  res: express.Response
): Promise<express.Response> => {
  const refreshToken = req.cookies.jwt;

  try {
    if (!refreshToken)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    const valid = await AuthService.getToken(refreshToken);

    if (!valid)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    await verifyRefreshToken(refreshToken);

    await AuthService.removeToken(refreshToken);

    res.clearCookie("jwt");

    return res.status(205).send({
      code: "auth/clear",
      message: "Token removed.",
    });
  } catch (error) {
    return res.status(401).send(error);
  }
};

export { create, authenticate, verifyAccess, createToken, clearToken };
