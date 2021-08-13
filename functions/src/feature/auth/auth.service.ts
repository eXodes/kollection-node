import { collection, usersCollection, metaDoc } from "../../enums/firestore";
import { ServiceError } from "../../factory/error";
import { hashPassword, verifyPassword } from "../../factory/password";
import { db } from "../../index";
import { AuthInput, AuthModel } from "./auth.types";

const AuthService = {
  create: async (body: AuthInput): Promise<AuthModel> => {
    const { username, password, name, email } = body;

    const usersRef = db.collection(collection.USERS);
    const userRef = usersRef.doc(username);
    const privateRef = userRef
      .collection(usersCollection.META)
      .doc(metaDoc.PRIVATE);

    const userData = await userRef.get();
    const emailSnapshot = await usersRef.where("email", "==", email).get();

    if (userData.exists || !emailSnapshot.empty)
      throw new ServiceError(
        "auth/user-exist",
        "Username or email already exist."
      );

    const batch = db.batch();

    batch.set(userRef, { id: username, name, email });
    batch.set(privateRef, { hash: hashPassword(password) });

    await batch.commit();

    const authData = (await userRef.get()).data();

    if (!authData)
      throw new ServiceError(
        "auth/process-error",
        "Server encounter error while processing data."
      );

    return authData as AuthModel;
  },

  authenticate: async (body: AuthInput): Promise<AuthModel> => {
    const { username, password } = body;

    const userRef = db.collection(collection.USERS).doc(username);
    const privateRef = userRef
      .collection(usersCollection.META)
      .doc(metaDoc.PRIVATE);

    const authData = await userRef.get();

    if (!authData.exists) {
      throw new ServiceError(
        "auth/invalid",
        "Username and password doesn't exist."
      );
    }

    const privateData = await privateRef.get();
    const verified = verifyPassword(password, privateData.data()?.hash);

    if (!verified)
      throw new ServiceError(
        "auth/invalid",
        "Username and password doesn't exist."
      );

    return authData.data() as AuthModel;
  },

  saveToken: async (username: string, refreshToken: string): Promise<void> => {
    try {
      const privateRef = db
        .collection(collection.USERS)
        .doc(username)
        .collection(usersCollection.META)
        .doc(metaDoc.PRIVATE);

      await privateRef.set({ token: refreshToken }, { merge: true });
    } catch (err) {
      console.error(err);
      throw new ServiceError("auth/invalid", "Refresh token doesn't exist.");
    }
  },

  getToken: async (username: string): Promise<string> => {
    try {
      const privateData = await db
        .collection(collection.USERS)
        .doc(username)
        .collection(usersCollection.META)
        .doc(metaDoc.PRIVATE)
        .get();

      return privateData.data()?.token;
    } catch {
      throw new ServiceError("auth/invalid", "Refresh token doesn't exist.");
    }
  },
};

export { AuthService };
