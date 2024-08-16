import { ContactsCollection } from '../models/contacts.js';

function getContacts() {
  return ContactsCollection.find();
}

 function getContactById(contactId) {
  return ContactsCollection.findById(contactId);
 }

function createContact(contact) {
  return ContactsCollection.create(contact);
}

function deleteContact(contactId) {
  return ContactsCollection.findByIdAndDelete(contactId);
}

async function  changeContact(contactId, name) {

  return  ContactsCollection.findByIdAndUpdate(contactId,{name},{ new: true});

}
export const updateContact = async (studentId, payload, options = {}) => {
  const rawResult = await ContactsCollection.findOneAndUpdate(
    { _id: studentId },
    payload,
    {
      new: true,
      includeResultMetadata: true,
      ...options,
    },
  );

  if (!rawResult || !rawResult.value) return null;

  return {
    student: rawResult.value,
    isNew: Boolean(rawResult?.lastErrorObject?.upserted),
  };
};
export {
  getContacts, getContactById, createContact, deleteContact, changeContact,
};
