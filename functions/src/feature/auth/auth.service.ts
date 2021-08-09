import { firestore } from "firebase-admin";
import { fs, fsUsers, fsUserDoc } from "../../enums/firestore";
import { ServiceError } from "../../factory/error";
import { hashPassword, verifyPassword } from "../../factory/password";
import { db } from "../../index";
import { AuthInput } from "./auth.types";

const AuthService = {
  create: async (body: AuthInput): Promise<firestore.DocumentData> => {
    const { username, password, name, email } = body;

    const usersRef = db.collection(fs.USERS);
    const userRef = usersRef.doc(username);
    const userData = await userRef.get();
    const privateRef = userRef.collection(fsUsers.META).doc(fsUserDoc.PRIVATE);
    const querySnapshot = await usersRef.where("email", "==", email).get();

    if (userData.exists || !querySnapshot.empty)
      throw new ServiceError(
        "auth/user-exist",
        "Username or email already exist."
      );

    const batch = db.batch();

    batch.set(userRef, { id: username, name, email });
    batch.set(privateRef, { hash: hashPassword(password) });

    await batch.commit();

    return (await userRef.get()).data()!;
  },

  authenticate: async (body: AuthInput): Promise<firestore.DocumentData> => {
    const { username, password } = body;

    const usersRef = db.collection(fs.USERS);
    const userRef = usersRef.doc(username);
    const privateRef = userRef.collection(fsUsers.META).doc(fsUserDoc.PRIVATE);

    const userData = await userRef.get();
    if (!userData.exists) {
      throw new ServiceError(
        "auth/invalid",
        "Username and password doesn't exist."
      );
    }

    const verified = verifyPassword(
      password,
      (await privateRef.get()).data()?.hash
    );
    if (!verified)
      throw new ServiceError(
        "auth/invalid",
        "Username and password doesn't exist."
      );

    return userData.data()!;
  },

  saveToken: async (
    username: string,
    refreshToken: string
  ): Promise<firestore.WriteResult> => {
    const tokenRef = db.collection(fs.TOKENS);

    const userRef = tokenRef && tokenRef.doc(username);
    return userRef && (await userRef.set({ refreshToken }));
  },

  getToken: async (token: string): Promise<boolean> => {
    const tokenRef = db.collection(fs.TOKENS);
    const querySnapshot = await tokenRef
      .where("refreshToken", "==", token)
      .get();

    return !querySnapshot.empty;
  },

  removeToken: async (token: string): Promise<boolean> => {
    const tokenRef = db.collection(fs.TOKENS);
    const querySnapshot = await tokenRef
      .where("refreshToken", "==", token)
      .get();

    return !querySnapshot.empty;
  },
};

export { AuthService };
