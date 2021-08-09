import isAlphanumeric from "validator/lib/isAlphanumeric";
import isEmail from "validator/lib/isEmail";
import { AuthInput } from "../feature/auth/auth.types";
import { ValidationError } from "./error";

const validate = (body: AuthInput): void => {
  const { name, email, username, password } = body;

  if (!username)
    throw new ValidationError(
      "auth/username-empty",
      "Username or email cannot be empty."
    );

  if (!password)
    throw new ValidationError(
      "auth/password-empty",
      "Password cannot be empty."
    );

  if (name?.length === 0)
    throw new ValidationError("auth/name-required", "Name is required.");

  if (email?.length === 0)
    throw new ValidationError("auth/email-required", "Email is required.");

  if (username?.length === 0)
    throw new ValidationError(
      "auth/username-required",
      "Username is required."
    );

  if (password?.length === 0)
    throw new ValidationError(
      "auth/password-required",
      "Password is required."
    );

  if (username?.length < 2)
    throw new ValidationError(
      "auth/username-invalid",
      "Username has to be  a at least 3 characters."
    );

  if (password?.length < 6)
    throw new ValidationError(
      "auth/password-invalid",
      "Password has to be  a at least 6 characters."
    );

  if (username) {
    const validated = isAlphanumeric(username, undefined, {});
    if (!validated)
      throw new ValidationError(
        "auth/username-invalid",
        "Username has to be alphanumeric only."
      );
  }

  if (email) {
    const validated = isEmail(email);
    if (!validated)
      throw new ValidationError(
        "auth/email-invalid",
        "Email has to be  a valid email."
      );
  }
};

export { validate };
