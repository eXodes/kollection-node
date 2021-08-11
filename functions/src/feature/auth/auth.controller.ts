import { Request, Response } from "express";
import { AuthenticationError } from "../../factory/error";
import {
  createAccessToken,
  createRefreshToken,
  decodeAccessToken,
  sendRefreshToken,
  verifyRefreshToken,
} from "../../factory/token";
import { validate } from "../../factory/validator";
import { AuthService } from "./auth.service";

const verify = async (req: Request, res: Response): Promise<Response> => {
  try {
    const authorization = req.headers["authorization"]!;
    const credentials = authorization?.split(" ")[1];

    const payload = await decodeAccessToken(credentials);

    return res.send({
      data: {
        username: payload.id,
        name: payload.name,
        email: payload.email,
      },
    });
  } catch (error) {
    return res.status(401).send(error);
  }
};

const create = async (req: Request, res: Response): Promise<Response> => {
  try {
    validate(req.body);

    const user = await AuthService.create(req.body);

    const token = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    await AuthService.saveToken(req.body.username, refreshToken);

    sendRefreshToken(res, refreshToken);

    return res.status(201).send({
      code: "auth/created",
      message: "User created.",
      data: { token },
    });
  } catch (error) {
    return res.status(400).send(error);
  }
};

const authenticate = async (req: Request, res: Response): Promise<Response> => {
  try {
    validate(req.body);

    const user = await AuthService.authenticate(req.body);

    const token = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    await AuthService.saveToken(req.body.username, refreshToken);

    sendRefreshToken(res, refreshToken);

    return res.status(200).send({
      code: "auth/authenticated",
      message: "User authenticated.",
      data: { token },
    });
  } catch (error) {
    return res.status(400).send(error);
  }
};

const refreshToken = async (req: Request, res: Response): Promise<Response> => {
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

    if (!payload.id)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    const token = createAccessToken({
      id: payload?.id,
      name: payload?.name,
      email: payload?.email,
    });

    return res.status(201).send({
      code: "auth/authorized",
      message: "New access token created.",
      data: { token },
    });
  } catch (error) {
    return res.status(401).send(error);
  }
};

const clearToken = async (req: Request, res: Response): Promise<Response> => {
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
      message: "Refresh token removed.",
    });
  } catch (error) {
    return res.status(401).send(error);
  }
};

export { verify, create, authenticate, refreshToken, clearToken };
