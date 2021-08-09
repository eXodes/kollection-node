import * as functions from "firebase-functions";
import admin from "firebase-admin";
import express from "express";
import cors from "cors";
import cookieParse from "cookie-parser";
import morgan from "morgan";
import helmet from "helmet";
import { authRoute } from "./feature/auth/auth.route";
import { authentication } from "./middleware/authentication";

const app = express();

// Firebase
admin.initializeApp();
export const db = admin.firestore();

// CORS
const origins = [
  "http://localhost:3000",
  "http://localhost:4000",
  "http://localhost:5000",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (origins.includes(origin!)) callback(null, true);
    },
  })
);

// Middleware
app.use(helmet());
app.use(cookieParse());
app.use(morgan("dev"));

// Routes
app.get("/", (_, res) => res.send("OK"));

app.use("/auth", authRoute);

app.use("/test", authentication, (_, res) => {
  res.send("OK");
});

export const api = functions.region("asia-southeast1").https.onRequest(app);
