import { parse } from 'valibot';

export const createValidationMiddleware = (schema) => {
  return (req, res, next) => {
    try {
      const validatedData = parse(schema, req.body);
      req.body = validatedData;
      next();
    } catch (error) {
      res.status(400).json({
        error: error.message
      });
    }
  };
}; 