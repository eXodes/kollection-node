import { JwtPayload } from "jsonwebtoken";

export type AuthInput<T = null> = {
  name?: string;
  email?: string;
  username: string;
  password: string;
  claims?: T | null;
};

export interface AuthModel {
  name: string;
  email: string;
  id: string;
}

export interface AuthPayload extends JwtPayload {
  id: string;
  name: string;
  email: string;
}

export interface RefreshPayload extends JwtPayload {
  id: string;
  version: number;
}
