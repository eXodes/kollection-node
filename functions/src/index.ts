import { https } from "firebase-functions";
import admin from "firebase-admin";
import express from "express";
import cors from "cors";
import cookieParse from "cookie-parser";
import morgan from "morgan";
// import helmet from "helmet";
import { authRoute } from "./feature/auth/auth.route";
import { authentication } from "./middleware/authentication";

const app = express();

// Firebase
admin.initializeApp();
export const db = admin.firestore();

// CORS
// const origins = [
//   "http://localhost:3000",
//   "http://localhost:4000",
//   "http://localhost:5000",
// ];

app.use(
  cors({
    origin: true,
  })
);

// Middleware
// app.use(helmet());
app.use(cookieParse());
app.use(morgan("dev"));

// Routes
app.get("/api", (req, res) => res.send({ status: "OK" }));

app.use("/api/auth", authRoute);

app.get("/api/test", authentication, (_, res) => res.send({ status: "OK" }));

export const api = https.onRequest(app);
