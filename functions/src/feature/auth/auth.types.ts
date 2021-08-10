export type AuthInput<T = null> = {
  name?: string;
  email?: string;
  username: string;
  password: string;
  claims?: T | null;
};
