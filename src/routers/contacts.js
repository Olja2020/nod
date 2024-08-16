
import express from "express";
import { isValidID } from '../middlewares/isValidId.js';
import { getContacts,getContactById,createContact,deleteContact,patchContact
} from '../controllers/contacts.js';
import { ctrlWrapper } from '../utils/ctrlWrapper.js';
import{createContactSchema, updateContactSchema} from "../validation/contacts.js";
import {validateBody} from "../middlewares/validateBody.js";
const router = express.Router();
const jsonParser=express.json();

router.get('/contacts', ctrlWrapper(getContacts));
router.get('/contacts/:contactId', isValidID, ctrlWrapper(getContactById));
router.post('/contacts',jsonParser, validateBody(createContactSchema), ctrlWrapper(createContact));
router.patch('/contacts/:contactId',isValidID, jsonParser,validateBody(updateContactSchema), ctrlWrapper(patchContact));
router.delete('/contacts/:contactId', isValidID, ctrlWrapper(deleteContact));
export default router;

