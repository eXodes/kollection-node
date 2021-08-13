import { Request, Response } from "express";
import { AuthenticationError } from "../../factory/error";
import {
  createAccessToken,
  createRefreshToken,
  decodeAccessToken,
  sendRefreshToken,
  decodeRefreshToken,
  clearRefreshToken,
} from "../../factory/token";
import { validate } from "../../factory/validator";
import { AuthService } from "./auth.service";

const verify = async (req: Request, res: Response): Promise<Response> => {
  try {
    const authorization = req.headers["authorization"]!;
    const credentials = authorization?.split(" ")[1];

    const payload = decodeAccessToken(credentials);

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

    const refreshToken = createRefreshToken({
      id: user.id,
      version: 0,
    });

    await AuthService.saveToken(user.id, refreshToken);

    const token = createAccessToken(user);

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

    const refreshToken = await AuthService.getToken(user.id);

    const token = createAccessToken(user);

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

const revalidateToken = async (
  req: Request,
  res: Response
): Promise<Response> => {
  try {
    const refreshToken = req.cookies.jwt;

    if (!refreshToken)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    const payload = decodeRefreshToken(refreshToken);

    const userRefreshToken = await AuthService.getToken(payload.id);

    if (!userRefreshToken)
      throw new AuthenticationError("auth/invalid", "Refresh token invalid.");

    const userPayload = decodeRefreshToken(userRefreshToken);

    if (payload.version !== userPayload.version)
      throw new AuthenticationError("auth/invalid", "Refresh token invalid.");

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
  try {
    const refreshToken = req.cookies.jwt;

    if (!refreshToken)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    const payload = decodeRefreshToken(refreshToken);

    const valid = await AuthService.getToken(payload.id);

    if (!valid)
      throw new AuthenticationError(
        "auth/unauthenticated",
        "Not authenticated."
      );

    const newRefreshToken = createRefreshToken({
      id: payload.id,
      version: payload.version + 1,
    });

    await AuthService.saveToken(payload.id, newRefreshToken);

    clearRefreshToken(res);

    return res.status(205).send({
      code: "auth/clear",
      message: "Refresh token removed.",
    });
  } catch (error) {
    return res.status(401).send(error);
  }
};

export { verify, create, authenticate, revalidateToken, clearToken };
