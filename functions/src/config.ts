import { config } from "firebase-functions";

export const ACCESS_TOKEN_MAX_AGE = 60 * 5;
export const REFRESH_TOKEN_MAX_AGE = 60 * 60 * 24 * 7;
export const ACCESS_SECRET = config().token.accessSecret;
export const REFRESH_SECRET = config().token.refreshSecret;
