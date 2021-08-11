import { JwtPayload } from "jsonwebtoken";

export type AuthInput<T = null> = {
  name?: string;
  email?: string;
  username: string;
  password: string;
  claims?: T | null;
};

export interface AuthPayload extends JwtPayload {
  id: string;
  name: string;
  email: string;
}
