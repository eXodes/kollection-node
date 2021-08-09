/**
 * Authentication Error
 */
export class AuthenticationError extends Error {
  readonly code: string;

  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code: string, message: string) {
    super(message);
    this.name = "AuthenticationError";
    this.code = code;
    this.message = message;

    return {
      name: this.name,
      code: this.code,
      message: this.message,
    };
  }
}

/**
 * Service Error
 */
export class ServiceError extends Error {
  readonly code: string;

  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code: string, message: string) {
    super(message);
    this.name = "ServiceError";
    this.code = code;
    this.message = message;

    return {
      name: this.name,
      code: this.code,
      message: this.message,
    };
  }
}

/**
 * Validation Error
 */
export class ValidationError extends Error {
  readonly code: string;

  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code: string, message: string) {
    super(message);
    this.name = "ValidationError";
    this.code = code;
    this.message = message;

    return {
      name: this.name,
      code: this.code,
      message: this.message,
    };
  }
}
