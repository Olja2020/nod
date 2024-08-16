import createHttpError from 'http-errors';

// export const validateBody = (schema) => async (req, res, next) => {
//   try {
//     await schema.validateAsync(req.body, {
//       abortEarly: false,
//     });
//     next();
//   } catch (err) {
//     console.error('Validation error:', err);
//     const error = createHttpError(400, 'Bad Request', {
//       errors: err.details,
//     });
//     next(error);
//   }
// };
export function validateBody(schema) {
  return async (req, res, next) => {
    try {
      await schema.validateAsync(req.body, { abortEarly: false });
     
      next();
    } catch (error) {
      console.log({ message: error.message });
      console.log({ details: error.details });

      next(
        createHttpError(
          400,
          error.details.map((err) => err.message).join(', '),
        ),
      );
    }
  };
}
