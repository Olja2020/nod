// import { isValidObjectId } from 'mongoose';
// import createHttpError from 'http-errors';

// export function isValidID(req, res, next) {
//   const { id } = req.params;

//   if (isValidObjectId(id) === false) {
//     return next(createHttpError(400, 'ID is not valid'));
//   }

//   next();
// }
import { isValidObjectId } from 'mongoose';
import createHttpError from 'http-errors';

export const isValidID = (req, res, next) => {
  const { contactId } = req.params;
 
  if (!isValidObjectId(contactId)) {
    throw createHttpError(404, 'Not found');
  }

  next();
};
