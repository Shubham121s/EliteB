class ErrorHandler extends Error {
    constructor(message, statusCode) {
      super(message);
      this.statusCode = statusCode;
  
      // Captures the stack trace, excluding this constructor call
      Error.captureStackTrace(this, this.constructor);
    }
  }
  
  module.exports = ErrorHandler;
  