//import { Router } from 'express';
import express from "express";
import { getContacts,getContactById,createContact,deleteContact,patchContact
} from '../controllers/contacts.js';
import { ctrlWrapper } from '../utils/ctrlWrapper.js';

const router = express.Router();
const jsonParser=express.json();

router.get('/contacts', ctrlWrapper(getContacts));
router.get('/contacts/:contactId', ctrlWrapper(getContactById));
router.post('/contacts',jsonParser, ctrlWrapper(createContact));
router.patch('/contacts/:contactId',jsonParser, ctrlWrapper(patchContact));
router.delete('/contacts/:contactId', ctrlWrapper(deleteContact));
export default router;

